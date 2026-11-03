//! A test-only global allocator that inspects every block as it is freed and counts
//! the frees that still contain a watched secret (phase 1 criterion 10: key buffers
//! are zeroised on every exit path). It sees Rust heap allocations only; aws-lc
//! allocates through its own `OPENSSL_malloc` and wipes on free.
//!
//! ```ignore
//! let w = guard::watch(&dek_bytes);
//! run_the_exit_path();
//! assert_eq!(w.leaks(), 0);
//! ```
//!
//! The only `unsafe` in the agent is here, and only in tests: a global allocator has
//! to implement the unsafe `GlobalAlloc` trait (DECISIONS.md).

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

const SLOTS: usize = 16;
const SECRET: usize = 32;

/// Watched secrets, in a fixed array so watching never allocates (the allocator takes
/// this lock while freeing, so the critical section must not allocate either).
static WATCHED: Mutex<[Option<[u8; SECRET]>; SLOTS]> = Mutex::new([None; SLOTS]);
static LEAKS: [AtomicUsize; SLOTS] = [const { AtomicUsize::new(0) }; SLOTS];

pub struct Guard;

// SAFETY: every allocation is delegated to `System` unchanged; `dealloc` only reads
// the block it is handed before passing it to `System::dealloc`.
unsafe impl GlobalAlloc for Guard {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: the caller upholds `GlobalAlloc::alloc`'s contract, which `System`
        // shares.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: the caller guarantees `ptr` was returned by this allocator for
        // `layout`, so `layout.size()` bytes at `ptr` are allocated and initialised
        // memory owned by the block until `System.dealloc` below.
        let block = unsafe { std::slice::from_raw_parts(ptr, layout.size()) };
        let watched = WATCHED.lock().unwrap_or_else(|p| p.into_inner());
        for (slot, secret) in watched.iter().enumerate() {
            if let Some(s) = secret
                && block.windows(SECRET).any(|w| w == s)
            {
                LEAKS[slot].fetch_add(1, Ordering::Relaxed);
            }
        }
        drop(watched);
        // SAFETY: same pointer and layout as the caller passed, freed exactly once.
        unsafe { System.dealloc(ptr, layout) }
    }
}

/// A watched secret; unwatched on drop.
pub struct Watch {
    slot: usize,
}

/// Starts counting frees of blocks that contain `secret`.
pub fn watch(secret: &[u8; SECRET]) -> Watch {
    let mut watched = WATCHED.lock().unwrap_or_else(|p| p.into_inner());
    let slot = watched
        .iter()
        .position(Option::is_none)
        .expect("fewer than 16 secrets are watched at once");
    watched[slot] = Some(*secret);
    LEAKS[slot].store(0, Ordering::Relaxed);
    Watch { slot }
}

impl Watch {
    /// Frees so far of blocks that still held the secret.
    pub fn leaks(&self) -> usize {
        LEAKS[self.slot].load(Ordering::Relaxed)
    }
}

impl Drop for Watch {
    fn drop(&mut self) {
        WATCHED.lock().unwrap_or_else(|p| p.into_inner())[self.slot] = None;
    }
}
