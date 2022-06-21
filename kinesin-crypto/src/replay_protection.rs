use std::vec::Vec;
use std::sync::RwLock;
use std::sync::atomic::AtomicUsize;

/// Concurrent replay protection implemented as a circular buffer.

pub struct ReplayProtectionInner {
    /// Offset from actual sequence number to head position
    pub start_offset: u64,
    /// Index into vec for current tail of circular buffer
    pub tail: usize,
    /// Vector as bitfield
    pub bitfield: Vec<AtomicUsize>
}

/// Replay protection implementation for unreliable datagrams
pub struct ReplayProtection {
    pub inner: RwLock<ReplayProtectionInner>
}

impl ReplayProtection {
    /// Construct new instance.
    /// `size` must be a multiple of `usize::BITS`.
    pub fn new(size: usize) -> Self {
        let mut bitfield = Vec::new();
        bitfield.resize_with(size / usize::BITS as usize, || AtomicUsize::new(0));
        ReplayProtection { 
            inner: RwLock::new(ReplayProtectionInner {
                start_offset: 0,
                tail: 0,
                bitfield
            })
        }
    }

    // pub fn set_index()
}
