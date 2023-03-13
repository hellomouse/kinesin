use parking_lot::RwLock;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::vec::Vec;

/// Concurrent replay protection implemented as a circular buffer.

pub struct ReplayProtectionInner {
    /// Offset from actual sequence number to head position
    pub start_offset: u64,
    /// Index into vec for current tail of circular buffer
    pub tail: usize,
    /// Vector as bitfield.
    /// `usize` is used to allow support for 32-bit platforms
    pub bitfield: Vec<AtomicUsize>,
}

/// Replay protection implementation for unreliable datagrams
pub struct ReplayProtection {
    pub inner: RwLock<ReplayProtectionInner>,
}

/// Describes result of ReplayProtection::resolve_index
#[derive(PartialEq)]
pub enum ResolveIndexResult {
    /// Requested index is before current window
    TooOld,
    /// Requested index is after current window
    TooNew,
    /// Requested index is in current window
    Found {
        /// Index of target element in ReplayProtectionInner::bitfield
        element: usize,
        /// Bitmask with only the bit representing the requested index set
        mask: usize,
    },
}

impl ReplayProtection {
    /// Construct new instance.
    pub fn new(size: usize) -> Self {
        let mut bitfield = Vec::new();
        let mut new_len = size / usize::BITS as usize;
        // ensure capacity for at least `size` bits
        if size % usize::BITS as usize > 0 {
            new_len += 1
        }
        // ensure even because i don't trust my ability to write code
        if new_len % 2 > 0 {
            new_len += 1
        }
        bitfield.resize_with(new_len, || AtomicUsize::new(0));
        ReplayProtection {
            inner: RwLock::new(ReplayProtectionInner {
                start_offset: 0,
                tail: 0,
                bitfield,
            }),
        }
    }

    /// Calculate bitfield element index and bitmask for requested index
    pub fn resolve_index(inner: &ReplayProtectionInner, index: u64) -> ResolveIndexResult {
        let bitfield_len = inner.bitfield.len() as u64;
        let usize_len = usize::BITS as u64;
        if index < inner.start_offset {
            ResolveIndexResult::TooOld
        } else if index - inner.start_offset >= bitfield_len * usize_len {
            ResolveIndexResult::TooNew
        } else {
            let element_raw_index = ((index - inner.start_offset) / usize_len) as usize;
            let element_index = (element_raw_index + inner.tail) % inner.bitfield.len();
            let bit_offset = index % usize_len;

            ResolveIndexResult::Found {
                element: element_index,
                mask: 1usize << bit_offset,
            }
        }
    }

    /// Advance current window forward to include `new_index`.
    /// If the current window already includes `new_index`, do nothing.
    pub fn advance_window(inner: &mut ReplayProtectionInner, new_index: u64) {
        // ensure window needs advancing
        if Self::resolve_index(inner, new_index) != ResolveIndexResult::TooNew {
            return;
        }
        let usize_len_u64 = usize::BITS as u64;
        let idx_from_tail = new_index - inner.start_offset;
        let el_aligned_index = idx_from_tail - (idx_from_tail % usize_len_u64);
        let el_offset_from_tail = idx_from_tail / usize_len_u64;

        // start with new_index at middle of window
        let half_bitfield = inner.bitfield.len() / 2;
        let mut el_shift = el_offset_from_tail - half_bitfield as u64;
        if el_shift > inner.bitfield.len() as u64 {
            // a large skip occurred and all previous state is out of the window, reinitialize
            // place new_index at center of window
            inner.start_offset += el_aligned_index - (half_bitfield as u64 * usize_len_u64);
            inner.tail = 0;
            inner.bitfield.fill_with(|| AtomicUsize::new(0));
        } else {
            // advance tail by el_shift, zeroing all elements along the way
            inner.start_offset += el_shift * usize_len_u64;
            while el_shift > 0 {
                *inner.bitfield[inner.tail].get_mut() = 0;
                inner.tail = (inner.tail + 1) % inner.bitfield.len();
                el_shift -= 1;
            }
        }
    }

    /// Test whether the provided index has been seen.
    /// Always use `set_index` whenever an index needs to be set, or races may occur.
    pub fn test_index(&self, index: u64) -> bool {
        let inner_read = self.inner.read();
        match ReplayProtection::resolve_index(&inner_read, index) {
            ResolveIndexResult::Found { element, mask } => {
                let current = inner_read.bitfield[element].load(Ordering::Relaxed);
                current & mask > 0
            }
            ResolveIndexResult::TooNew => {
                false
            }
            ResolveIndexResult::TooOld => {
                true
            }
        }
    }

    /// Mark the provided index as seen.
    /// Return whether the index was already seen.
    pub fn set_index(&self, index: u64) -> bool {
        loop {
            let inner_read = self.inner.read();
            match ReplayProtection::resolve_index(&inner_read, index) {
                ResolveIndexResult::Found { element, mask } => {
                    // TODO: learn about memory order rofl
                    let old = inner_read.bitfield[element].fetch_or(mask, Ordering::Relaxed);
                    return old & mask > 0;
                }
                ResolveIndexResult::TooNew => {
                    drop(inner_read);
                    let mut inner_write = self.inner.write();
                    ReplayProtection::advance_window(&mut inner_write, index);
                    continue;
                }
                ResolveIndexResult::TooOld => {
                    return true;
                }
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::ReplayProtection;

    #[test]
    fn basic() {
        let rp = ReplayProtection::new(256);
        assert!(!rp.set_index(0));
        assert!(!rp.set_index(1));
        assert!(!rp.set_index(128));
        assert!(rp.set_index(0));
        assert!(rp.set_index(1));
        assert!(rp.set_index(128));

        assert!(rp.test_index(0));
        assert!(!rp.test_index(3));
        assert!(rp.test_index(128));
    }

    #[test]
    fn move_window() {
        let mut rp = ReplayProtection::new(256);
        assert!(!rp.set_index(0));
        assert!(!rp.set_index(5));
        assert!(!rp.set_index(250));

        // test window shift
        assert!(!rp.set_index(260));
        assert!(rp.set_index(1));
        assert!(rp.test_index(2));
        assert!(rp.set_index(250));

        // test max values
        assert!(!rp.set_index(u64::MAX));
        assert!(rp.test_index(u64::MAX));

        rp = ReplayProtection::new(256);
        assert!(!rp.set_index(u64::MAX - 1));
        assert!(!rp.test_index(u64::MAX));
        assert!(!rp.set_index(u64::MAX));
        assert!(rp.test_index(u64::MAX));
    }

    use std::sync::Arc;
    use std::thread::{self, JoinHandle};

    const THREADS: u64 = 32;
    const PER_THREAD: u64 = 65536;
    const RP_SIZE: usize = 8192;

    fn join_for_counts(threads: Vec<JoinHandle<u64>>) -> Vec<u64> {
        let total_counts: Vec<u64> = threads
            .into_iter()
            .map(|t| t.join().expect("oh no, thread crashed"))
            .collect();

        println!(
            "replay_protection success counts per thread: {}",
            total_counts
                .iter()
                .map(|c| c.to_string())
                .collect::<Vec<String>>()
                .join(", ")
        );

        total_counts
    }

    #[test]
    fn spam_threads_no_collide() {
        let rp = Arc::new(ReplayProtection::new(RP_SIZE));
        let mut threads = Vec::new();

        for tno in 0..THREADS {
            let rp_cloned = rp.clone();
            let t = thread::spawn(move || {
                let mut succeeded: u64 = 0;
                for i in 0..PER_THREAD {
                    if !rp_cloned.set_index(i * THREADS + tno) {
                        succeeded += 1;
                    }
                }
                succeeded
            });
            threads.push(t);
        }

        let total_counts = join_for_counts(threads);

        let total = THREADS * PER_THREAD;
        let rp_base = rp.inner.read().start_offset;
        for i in rp_base..(THREADS * PER_THREAD) {
            assert!(rp.test_index(i));
        }
        
        // sanity
        let sum = total_counts.iter().sum::<u64>();
        println!("sum {}, total {}", sum, total);
        assert!(sum <= total);
    }

    #[test]
    fn spam_threads_but_collide() {
        let rp = Arc::new(ReplayProtection::new(RP_SIZE));
        let mut threads = Vec::new();

        for _ in 0..THREADS {
            let rp_cloned = rp.clone();
            let t = thread::spawn(move || {
                let mut succeeded: u64 = 0;
                for i in 0..PER_THREAD {
                    if !rp_cloned.set_index(i) {
                        succeeded += 1;
                    }
                }
                succeeded
            });
            threads.push(t);
        }

        let total_counts = join_for_counts(threads);

        // ensure filled
        let rp_base = rp.inner.read().start_offset;
        for i in rp_base..PER_THREAD {
            assert!(rp.test_index(i));
        }

        // if this works there have probably been no collisions
        assert_eq!(total_counts.iter().sum::<u64>(), PER_THREAD);
    }
}
