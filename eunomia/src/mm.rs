//! Bump allocator with `GlobalAlloc` support.
//!
//! Provides a simple bump allocator that hands out memory from a
//! contiguous heap region.  No `dealloc` — freed memory is not
//! reclaimed (sufficient for test workloads and simple applications).
//!
//! Implements `GlobalAlloc` so the Rust `alloc` crate (Vec, Box,
//! String, etc.) works out of the box.

use core::alloc::{GlobalAlloc, Layout};
use core::sync::atomic::{AtomicUsize, Ordering};

/// Default heap size: 1 MiB.
const DEFAULT_HEAP_SIZE: usize = 1 << 20;

// Linker-provided symbol marking the start of the heap region.
extern "C" {
    static __heap_start: u8;
}

/// A lock-free bump allocator.
///
/// Allocations advance an atomic pointer.  Deallocation is a no-op.
/// Thread-safe via `fetch_add` on the bump pointer.
pub struct BumpAllocator {
    heap_start: AtomicUsize,
    heap_end: AtomicUsize,
    next: AtomicUsize,
    allocated: AtomicUsize,
}

impl BumpAllocator {
    /// Create an uninitialised allocator (must call `init` before use).
    pub const fn new() -> Self {
        Self {
            heap_start: AtomicUsize::new(0),
            heap_end: AtomicUsize::new(0),
            next: AtomicUsize::new(0),
            allocated: AtomicUsize::new(0),
        }
    }

    /// Initialise the allocator with the heap region from the linker script.
    ///
    /// # Safety
    /// Must be called exactly once, before any allocation.
    pub unsafe fn init(&self) {
        let start = &raw const __heap_start as usize;
        let end = start + DEFAULT_HEAP_SIZE;
        self.heap_start.store(start, Ordering::Release);
        self.heap_end.store(end, Ordering::Release);
        self.next.store(start, Ordering::Release);
    }

    /// Initialise with an explicit region (useful for testing).
    ///
    /// # Safety
    /// The memory region `[start, start + size)` must be valid and unused.
    pub unsafe fn init_with(&self, start: usize, size: usize) {
        self.heap_start.store(start, Ordering::Release);
        self.heap_end.store(start + size, Ordering::Release);
        self.next.store(start, Ordering::Release);
    }

    /// Total bytes allocated (including alignment padding).
    pub fn allocated(&self) -> usize {
        self.allocated.load(Ordering::Relaxed)
    }

    /// Remaining bytes in the heap.
    pub fn remaining(&self) -> usize {
        let next = self.next.load(Ordering::Relaxed);
        let end = self.heap_end.load(Ordering::Relaxed);
        end.saturating_sub(next)
    }

    /// Heap start address.
    pub fn heap_start(&self) -> usize {
        self.heap_start.load(Ordering::Relaxed)
    }

    /// Heap end address.
    pub fn heap_end(&self) -> usize {
        self.heap_end.load(Ordering::Relaxed)
    }

    /// Allocate `size` bytes with the given alignment.
    fn bump_alloc(&self, size: usize, align: usize) -> Option<*mut u8> {
        loop {
            let current = self.next.load(Ordering::Relaxed);
            let aligned = (current + align - 1) & !(align - 1);
            let new_next = aligned + size;

            if new_next > self.heap_end.load(Ordering::Relaxed) {
                return None; // OOM
            }

            // CAS loop for lock-free bump.
            match self.next.compare_exchange_weak(
                current,
                new_next,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => {
                    self.allocated.fetch_add(new_next - current, Ordering::Relaxed);
                    return Some(aligned as *mut u8);
                }
                Err(_) => continue, // Retry on contention.
            }
        }
    }
}

unsafe impl GlobalAlloc for BumpAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        match self.bump_alloc(layout.size(), layout.align()) {
            Some(ptr) => ptr,
            None => core::ptr::null_mut(),
        }
    }

    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {
        // Bump allocator: dealloc is a no-op.
    }
}

// The allocator must be Sync for GlobalAlloc.
unsafe impl Sync for BumpAllocator {}

#[global_allocator]
static ALLOCATOR: BumpAllocator = BumpAllocator::new();

/// Initialise the global heap allocator.
///
/// # Safety
/// Must be called exactly once during early boot, before any `alloc` use.
pub unsafe fn init() {
    ALLOCATOR.init();
}

/// Returns the global allocator for status queries.
pub fn allocator() -> &'static BumpAllocator {
    &ALLOCATOR
}
