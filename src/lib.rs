#![feature(pointer_is_aligned)]
#![feature(strict_provenance)]
#![feature(pointer_byte_offsets)]

use core::{mem::{transmute, MaybeUninit, align_of, transmute_copy, forget}, sync::atomic::{AtomicUsize}, marker::PhantomData, ptr::addr_of};
use std::{sync::atomic::{AtomicU16, Ordering, fence}, cell::UnsafeCell, thread, ptr::{null_mut, slice_from_raw_parts}, mem::size_of};
pub use errno;
use libc::{self, PROT_READ, PROT_WRITE, MAP_ANONYMOUS, MAP_PRIVATE, MAP_HUGE_2MB, ENOMEM, MAP_FAILED};

const SMALL_PAGE_SIZE: usize = 4096;
const PAGE_2MB_SIZE: usize = 1 << 21;
const PAGE_2MB_ALIGN: usize = 1 << 21;
const SMALL_PAGE_LIMIT: usize = PAGE_2MB_SIZE / 4096;

pub struct PageAllocator {
  super_page_start: UnsafeCell<*mut [u8;4096]>,
  index: AtomicUsize,
}
unsafe impl Sync for PageAllocator {}
impl PageAllocator {
  fn alloc_superpage() -> Option<*mut u8> { unsafe {
    let mut mem = libc::mmap64(
        null_mut(),
        PAGE_2MB_SIZE,
        PROT_READ | PROT_WRITE,
        MAP_ANONYMOUS | MAP_PRIVATE | MAP_HUGE_2MB,
        -1,
        0);
    if mem == MAP_FAILED {
      return None;
    }
    let out = libc::posix_memalign(&mut mem, PAGE_2MB_ALIGN, PAGE_2MB_SIZE);
    if out != 0 {
      return None;
    }
    return Some(mem.cast())
  } }
  pub fn new() -> Self {
    Self {
      super_page_start: UnsafeCell::new(null_mut()),
      index: AtomicUsize::new(SMALL_PAGE_LIMIT << 1)
    }
  }
  #[inline(never)]
  pub fn try_get_page_nonblocking(&self) -> Option<Block4KPtr> {
    let offset = self.index.fetch_add(1 << 1, Ordering::Relaxed);
    let locked = offset & 1 == 1;
    if locked { return None }
    let mut index = offset >> 1;
    let did_overshoot = index >= SMALL_PAGE_LIMIT;
    if did_overshoot {
      let item = self.index.fetch_or(1, Ordering::Relaxed);
      let already_locked = item & 1 == 1;
      if already_locked {
        errno::set_errno(errno::Errno(libc::EWOULDBLOCK));
        return None
      }
      else { // we gotta provide new page
        let page = Self::alloc_superpage()?;
        unsafe { *self.super_page_start.get() = page.cast() };
        self.index.store(1 << 1, Ordering::Release);
        index = 0;
      }
    };
    fence(Ordering::Acquire); // we must see that page got allocated
    let ptr = unsafe { (*self.super_page_start.get()).add(index) };
    return Some(Block4KPtr(ptr.cast()));
  }
  pub fn try_get_page_blocking(&self) -> Option<Block4KPtr> {
    loop {
      if let k@Some(_) = self.try_get_page_nonblocking() {
        return k;
      } else {
        let errno = errno::errno();
        match errno.0 {
          libc::EWOULDBLOCK => continue,
          _ => return None
        }
      }
    }
  }
}
#[derive(Debug)]
pub struct Block4KPtr(*mut [u8;4096]);
impl Block4KPtr {
  pub fn new(ptr: *mut ()) -> Self {
    assert!(ptr.is_aligned_to(4096), "misaligned ptr given to Block4KPtr");
    return Self(ptr.cast())
  }
  pub fn get_data_ptr(&self) -> *mut u8 {
    self.0 as _
  }
  pub fn is_null(&self) -> bool {
    self.0.expose_addr() == 0
  }
}

#[test]
fn alloc_works() {
  // this will eat a lot of ram, fix it if not disposed properly
  const THREAD_COUNT:usize = 4096;
  let ralloc = PageAllocator::new();
  let ptrs: [*mut u32;THREAD_COUNT] = [null_mut(); THREAD_COUNT];
  thread::scope(|s|{
    for i in 0 .. THREAD_COUNT {
      let unique_ref = &ralloc;
      let fuck = addr_of!(ptrs) as u64 ;
      s.spawn(move || {
        let ptr;
        loop {
          if let Some(ptr_) = unique_ref.try_get_page_nonblocking() {
            ptr = ptr_; break;
          };
        }
        let Block4KPtr(v) = ptr;
        for ix in 0 .. (4096 / size_of::<u32>()) {
          unsafe { *v.cast::<u32>().add(ix) = i as u32; }
        }
        unsafe { *transmute::<_, *mut u64>(fuck).add(i) = v as u64 };
      });
    }
  });
  for i in 0 .. THREAD_COUNT {
    let ptr = ptrs[i];
    let sl : &[u32] = unsafe { &*slice_from_raw_parts(ptr, 4096 / size_of::<u32>()) };
    for s in sl {
        assert!(*s == i as u32, "threads got same memory region!!!");
    }
  }
}
#[repr(C)]
struct RegionMetadata {
  ref_count: AtomicU16
}
#[repr(C)] #[repr(align(4096))]
struct Page {
  metadata: RegionMetadata,
  bytes: MaybeUninit<[u8; SMALL_PAGE_SIZE - size_of::<RegionMetadata>()]>
}
const _ : () = if size_of::<Page>() != SMALL_PAGE_SIZE { panic!() } ;

enum AllocatorStateTag {
  Uninit,
  Operational,
  Poisoned
}
struct AllocatorStateData {
  current_page_start: *mut Page,
  allocation_tail: *mut u8,
}
struct SubRegionAllocatorInner {
  tag: AllocatorStateTag,
  data: AllocatorStateData
}
pub struct SubRegionAllocator(UnsafeCell<SubRegionAllocatorInner>);
impl SubRegionAllocator {
  pub fn new() -> Self {
    Self(UnsafeCell::new(SubRegionAllocatorInner {
      tag: AllocatorStateTag::Uninit,
      data: AllocatorStateData { current_page_start: null_mut(), allocation_tail: null_mut() }
    }))
  }
  // true if still needs page
  fn release_page(
    &self,
  ) -> bool { unsafe {
    let this = &mut*self.0.get();
    let prior_count =
      (*this.data.current_page_start).metadata.ref_count.fetch_sub(1, Ordering::Relaxed);
    if prior_count == 1 {
      // extremely rare situation , when we can reuse current page.
      // there is no need to sync with other threads rws
      // since we dont use anything they have done .
      // their writes wont appear out of nowhere.
      // wont they?
      fence(Ordering::Acquire);
      this.data.allocation_tail =
        this.data.current_page_start.cast::<u8>().byte_add(size_of::<RegionMetadata>());
      return false;
    } else {
      return true;
    }
  } }
  fn set_new_page(&self, block:Block4KPtr) { unsafe {
    let new_page_ptr = block.get_data_ptr().cast::<Page>();
    {
      let ptr = &mut *new_page_ptr;
      // this has to be born with ref count +1 to not allow for
      // situation when other worker possesing objects within this region
      // consumes this region . this would cause racing
      ptr.metadata.ref_count = AtomicU16::new(1);
    };
    let this = &mut*self.0.get();
    this.data.current_page_start = new_page_ptr;
    this.data.allocation_tail = new_page_ptr.cast::<u8>().byte_add(size_of::<RegionMetadata>());
  } }
  pub fn alloc_bytes(
    &self,
    byte_size: usize,
    alignment: usize,
    free_page_provider: &mut impl FnMut() -> Option<Block4KPtr>
  ) -> Option<OpaqueRegionItemRef> { unsafe {
    if byte_size == 0 {
      errno::set_errno(errno::Errno(libc::EINVAL));
      return None
    }
    let reserved_space = size_of::<RegionMetadata>().next_multiple_of(alignment);
    if byte_size >= SMALL_PAGE_SIZE - reserved_space {
      // cant reasonably handle this yet
      errno::set_errno(errno::Errno(libc::EINVAL));
      return None;
    }
    let this = &mut*self.0.get();
    loop {
    match this.tag {
      AllocatorStateTag::Uninit => {
        let smth = free_page_provider();
        if smth.is_none() { return None; }
        self.set_new_page(smth.unwrap());
        this.tag = AllocatorStateTag::Operational;
        continue;
      },
      AllocatorStateTag::Poisoned => {
        let needs_page = self.release_page();
        if needs_page {
          let smth = free_page_provider();
          if smth.is_none() { return None; }
          self.set_new_page(smth.unwrap());
        }
        this.tag = AllocatorStateTag::Operational;
        continue;
      },
      AllocatorStateTag::Operational => {
        'attempt:loop {
          let mut ptr = this.data.allocation_tail;
          ptr = ptr.byte_add(ptr.align_offset(alignment));
          let next_allocation_tail = ptr.byte_add(byte_size);
          let region_end_addr =
            this.data.current_page_start.expose_addr() + SMALL_PAGE_SIZE;
          let next_alloc_addr = next_allocation_tail.expose_addr();
          let doesnt_fit = next_alloc_addr > region_end_addr;
          if doesnt_fit {
            // here we need to release current page (effectively detaching it from this worker)
            // and making current page amenable for consumption by last user of some object,
            // residing within the region backed by current page.
            // all regions have owning worker until they become full, at which point they
            // have to be detached and recycled by last user (worker)
            let need_repage = self.release_page();
            if need_repage {
              let smth = free_page_provider();
              if smth.is_none() { return None; }
              self.set_new_page(smth.unwrap());
              continue 'attempt;
            }
          }
          let _ = (*this.data.current_page_start)
            .metadata.ref_count.fetch_add(1, Ordering::AcqRel);

          this.data.allocation_tail = next_allocation_tail;
          if next_alloc_addr == region_end_addr {
            this.tag = AllocatorStateTag::Poisoned;
          }

          return Some(OpaqueRegionItemRef::new(ptr.cast()));
        }
      },
    } }
  }; }
  pub fn dispose_object<T:RegionPtrObject>(object: T) -> Option<Block4KPtr> { unsafe {
    let rptr = object.destruct().get_region_origin_ptr();
    let i = (*rptr).ref_count.fetch_sub(1, Ordering::Release) ;
    if i == 1 {
      fence(Ordering::Acquire);
      return Some(Block4KPtr::new(rptr.cast::<()>()));
    }
    return None
  } }
  pub fn alloc_object<T>(
    &self,
    free_page_provider: &mut impl FnMut() -> Option<Block4KPtr>
  ) -> Option<RegionBoxRef<MaybeUninit<T>>> {
    let ptr = self.alloc_bytes(size_of::<T>(), align_of::<T>(), free_page_provider)?;
    return Some(RegionBoxRef(ptr, PhantomData));
  }
  #[inline(never)]
  fn alloc_byte_array(
    &self,
    item_size:usize,
    item_align:usize,
    item_count:usize,
    free_page_provider: &mut dyn FnMut() -> Option<Block4KPtr>
  ) -> Option<RawByteArrayRef> { unsafe {
    let this = &mut*self.0.get();
    'state:loop {
      match this.tag {
        AllocatorStateTag::Uninit => {
          let smth = free_page_provider();
          if smth.is_none() { return None; }
          self.set_new_page(smth.unwrap());
          this.tag = AllocatorStateTag::Operational;
          continue 'state;
        },
        AllocatorStateTag::Poisoned => {
          let needs_page = self.release_page();
          if needs_page {
            let smth = free_page_provider();
            if smth.is_none() { return None; }
            self.set_new_page(smth.unwrap());
          }
          this.tag = AllocatorStateTag::Operational;
          continue 'state;
        },
        AllocatorStateTag::Operational => break 'state,
      }
    }
    let mut first = true;
    let mut failed = false;
    let mut remaining_count = item_count;
    let mut first_ptr = null_mut();
    let mut tail_ptr = null_mut();
    loop {
      let tail = this.data.allocation_tail;
      let (mtd_size, mtd_align) = if first {
        type T = ByteArrayHeadMetadata;
        (size_of::<T>(), align_of::<T>())
      } else {
        type T = ByteArrayTailMetadata;
        (size_of::<T>(), align_of::<T>())
      };
      let arr_metadata_ptr =
        tail.byte_add(tail.align_offset(mtd_align));
      let data_ptr_unal = arr_metadata_ptr.byte_add(mtd_size);
      let data_ptr_al = data_ptr_unal.byte_add(data_ptr_unal.align_offset(item_align));
      let data_has_overalign = data_ptr_al.expose_addr() != data_ptr_unal.expose_addr();
      let arr_metadata_ptr = if data_has_overalign {
        let near_ptr = data_ptr_al.byte_sub(mtd_size);
        assert!(near_ptr.expose_addr() >= arr_metadata_ptr.expose_addr());
        near_ptr
      } else {
        arr_metadata_ptr
      };
      let end = this.data.current_page_start.expose_addr() + SMALL_PAGE_SIZE;
      let page_byte_cap = end - data_ptr_al.expose_addr();
      let needs_another_page = (remaining_count * item_size) > page_byte_cap;
      if needs_another_page {
        let _ = (*this.data.current_page_start)
          .metadata.ref_count.fetch_add(1, Ordering::Relaxed);
        let need_repage = self.release_page();
        if need_repage {
          let smth = free_page_provider();
          if smth.is_none() {
            failed = true;
            break;
          }
          self.set_new_page(smth.unwrap());
        }
        let remc = page_byte_cap / item_size;
        if first {
          first_ptr = data_ptr_al;
          tail_ptr = data_ptr_al;
          let mtd =
            tail_ptr.byte_sub(mtd_size).cast::<ByteArrayHeadMetadata>().as_mut().unwrap();
          mtd.next_chunk = data_ptr_al;
          mtd.chunk_length = remc;
          mtd.total_item_count = item_count;
          first = false
        } else {
          let mtd =
            tail_ptr.byte_sub(mtd_size).cast::<ByteArrayTailMetadata>().as_mut().unwrap();
          mtd.next_chunk = data_ptr_al;
          mtd.chunk_length = remc;
          tail_ptr = data_ptr_al;
        }
        remaining_count -= remc;
        continue;
      } else {
        if first {
          arr_metadata_ptr.cast::<ByteArrayHeadMetadata>().write(ByteArrayHeadMetadata {
            chunk_length: item_count,
            total_item_count: item_count,
            next_chunk: null_mut(),
          });
          first_ptr = data_ptr_al;
          tail_ptr = data_ptr_al;
        } else {
          let mtd =
            tail_ptr.byte_sub(mtd_size).cast::<ByteArrayTailMetadata>().as_mut().unwrap();
          mtd.chunk_length = remaining_count;
          mtd.next_chunk = null_mut();
        }
        let tail = data_ptr_al.byte_add(remaining_count * item_size);
        this.data.allocation_tail = tail;
        break;
      }
    }
    if failed {
      // undo our doings.
      // trace the chunk chain and release taken pages
      return None;
    }
    if this.data.allocation_tail.expose_addr() ==
    this.data.current_page_start.expose_addr() + SMALL_PAGE_SIZE {
      this.tag = AllocatorStateTag::Poisoned;
    };
    let ptr = RawByteArrayRef {
      first_chunk: first_ptr,
      tail_chunk: tail_ptr
    };
    return Some(ptr);
  } }
  pub fn alloc_array<T>(
    &self,
    item_count:usize,
    free_page_provider: &mut impl FnMut() -> Option<Block4KPtr>
  ) -> Option<ArrayRef<MaybeUninit<T>>> {
    let ar = self.alloc_byte_array(
      size_of::<T>(), align_of::<T>(), item_count, free_page_provider)?;
    return Some(ArrayRef(ar, PhantomData));
  }
}
#[repr(C)]
struct ByteArrayHeadMetadata {
  total_item_count: usize,
  next_chunk: *mut u8,
  chunk_length: usize,
}
#[repr(C)]
struct ByteArrayTailMetadata {
  next_chunk: *mut u8,
  chunk_length: usize,
}
#[repr(C)]
struct ByteArrayGenericMetadata {
  next_chunk: *mut u8,
  chunk_length: usize,
}
#[derive(Debug)]
struct RawByteArrayRef {
  first_chunk: *mut u8,
  tail_chunk: *mut u8
}
pub struct ArrayRef<T>(RawByteArrayRef, PhantomData<T>);
impl <T> ArrayRef<T> {
  pub fn len(&self) -> usize { unsafe {
    let head_mtd_ptr = self.0.first_chunk.byte_sub(size_of::<ByteArrayHeadMetadata>());
    (*head_mtd_ptr.cast::<ByteArrayHeadMetadata>()).total_item_count
  } }
}
pub struct ArrayIterator<T>(UnsafeCell<ArrayIteratorInner<T>>);
struct ArrayIteratorInner<T> {
  storage: ArrayRef<T>,
  index: usize
}
impl<T> ArrayIterator<T> {
  pub fn new(array_ref: ArrayRef<T>) -> Self {
    ArrayIterator(UnsafeCell::new(ArrayIteratorInner {
      storage: array_ref, index: 0
    }))
  }
  pub fn dispose(self) -> ArrayRef<T> {
    let this = unsafe{self.0.get().read()};
    forget(self);
    this.storage
  }
  pub fn extend_capacity(
    &self,
    additional_item_count:usize,
    mem_provider:&SubRegionAllocator
  ) -> bool {
    todo!()
  }
  pub fn push(&self, item: T) -> bool {
    todo!()
  }
  pub fn pop(&self) -> Option<T> {
    todo!()
  }
}



#[derive(Debug, Clone, Copy)]
pub struct OpaqueRegionItemRef(u64);
impl OpaqueRegionItemRef {
  pub fn new_null() -> Self {
    OpaqueRegionItemRef(0)
  }
  pub fn is_null(&self) -> bool {
    self.0 == 0
  }
  pub fn new(
    region_segment_addr: *mut (),
  ) -> Self {
    Self(region_segment_addr.expose_addr() as u64)
  }
  pub fn get_data_ptr(&self) -> *mut () {
    self.0 as _
  }
  fn get_region_origin_ptr(&self) -> *mut RegionMetadata {
    (self.0 & !((1 << 12) - 1)) as _
  }
  pub fn cast<T>(self) -> RegionBoxRef<T> {
    RegionBoxRef(self, PhantomData)
  }
}

pub struct RegionBoxRef<T>(OpaqueRegionItemRef, PhantomData<T>);
impl <T> RegionBoxRef<T> {
  pub fn is_null(&self) -> bool { self.0.is_null() }
  pub fn deref(&self) -> &T {
    unsafe { &*self.0.get_data_ptr().cast::<T>() }
  }
  pub fn deref_mut(&mut self) -> &mut T {
    unsafe { &mut *self.0.get_data_ptr().cast::<T>() }
  }
  pub fn deref_raw(&self) -> *mut T {
    self.0.get_data_ptr().cast()
  }
}
impl <T> RegionBoxRef<MaybeUninit<T>> {
  pub fn init(mut self, value:T) -> RegionBoxRef<T> {
    self.deref_mut().write(value);
    return RegionBoxRef(self.0, PhantomData);
  }
}
pub trait RegionPtrObject {
  fn destruct(self) -> OpaqueRegionItemRef;
}
impl <T> RegionPtrObject for RegionBoxRef<T> {
  fn destruct(self) -> OpaqueRegionItemRef {
    self.0
  }
}

#[test]
fn inout() {
  let palloc = PageAllocator::new();
  let sralloc = SubRegionAllocator::new();
  let mut prov = || palloc.try_get_page_blocking();
  let mut v = vec![];
  const LIMIT: u16 = 4096 ;
  for i in 0 .. LIMIT {
    let obj = sralloc.alloc_object::<u16>(&mut prov).unwrap();
    let obj = obj.init(i);
    v.push(obj)
  }
  for i in 0 .. LIMIT {
    let val = v[i as usize].deref();
    assert!(i == *val)
  }
  let mut p = vec![];
  for i in 0 .. LIMIT {
    let r = unsafe { transmute_copy::<_, RegionBoxRef<u16>>(&v[i as usize]) };
    if let Some(thing) = SubRegionAllocator::dispose_object(r) {
      p.push(thing)
    }
  }
  // println!("{:#?}", p);
  assert!(p.len() == 2)
}
#[test]
fn arr () {
  let palloc = PageAllocator::new();
  let sralloc = SubRegionAllocator::new();
  let mut prov = || palloc.try_get_page_blocking();
  type Item = u16;
  let arr = sralloc.alloc_array::<Item>(2048, &mut prov).unwrap();

  println!("{:?}", arr.len())
}