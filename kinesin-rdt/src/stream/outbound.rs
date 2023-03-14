use std::collections::{HashSet, VecDeque};
use std::ops::Range;

use tracing::trace;

use crate::common::range_set::RangeSet;

pub enum RetransmitStrategy {
    Reliable,
    Unreliable,
    Deadline { limit: u64 },
}

/// default outbound buffer size limit
pub const OUTBOUND_BUFFER_DEFAULT_LIMIT: u64 = 64 * 1024 * 1024;

/// stream outbound delivery
pub struct StreamOutboundState {
    /// buffer for outbound data
    pub buffer: VecDeque<u8>,
    /// stream offset at which buffer starts
    pub buffer_offset: u64,
    /// outbound buffer size limit
    pub buffer_limit: u64,

    /// segments queued for (re)transmission
    pub queued: RangeSet,
    /// segments successfully delivered (retransmission unnecessary)
    pub delivered: RangeSet,
    /// offsets into the stream where messages begin, if applicable
    pub message_offsets: HashSet<u64>,

    /// if we're still in the initial state (window limit not received yet)
    pub is_initial_window: bool,
    /// peer inbound flow control receive limit
    pub window_limit: u64,
    /// retransmission strategy on packet loss
    pub retransmit_strategy: RetransmitStrategy,

    /// callback on writable
    pub writable_callback: Option<Box<dyn FnMut()>>,
    /// whether writable_callback will be called
    pub writable_callback_active: bool,
    /// callback on readable
    pub readable_callback: Option<Box<dyn FnMut()>>,
    /// whether readable_callback will be called
    pub readable_callback_active: bool,
}

impl StreamOutboundState {
    pub fn new(
        initial_window_limit: u64,
        retransmit_strategy: RetransmitStrategy,
        writable_callback: Option<Box<dyn FnMut()>>,
        readable_callback: Option<Box<dyn FnMut()>>,
    ) -> StreamOutboundState {
        StreamOutboundState {
            buffer: VecDeque::new(),
            buffer_offset: 0,
            buffer_limit: OUTBOUND_BUFFER_DEFAULT_LIMIT,
            queued: RangeSet::unlimited(),
            delivered: RangeSet::unlimited(),
            message_offsets: HashSet::new(),
            is_initial_window: true,
            window_limit: initial_window_limit,
            retransmit_strategy,
            writable_callback,
            writable_callback_active: false,
            readable_callback,
            readable_callback_active: false,
        }
    }

    /// gets how many bytes are currently writable to the stream
    pub fn writable(&self) -> u64 {
        let rwnd_limit = self.window_limit.saturating_sub(self.buffer_offset);
        let real_limit = u64::min(rwnd_limit, self.buffer_limit);
        real_limit.saturating_sub(self.buffer.len() as u64)
    }

    /// determine whether any segment is currently sendable
    pub fn readable(&self) -> bool {
        if let Some(next_segment) = self.queued.peek_first() {
            next_segment.start < self.window_limit
        } else {
            false
        }
    }

    /// call writable_callback if writable
    pub fn notify_if_writable(&mut self) {
        if self.writable() == 0 || !self.writable_callback_active {
            return;
        }
        if let Some(ref mut callback) = self.writable_callback {
            self.writable_callback_active = false;
            callback();
        }
    }

    /// call readable_callback if readable
    pub fn notify_if_readable(&mut self) {
        if self.readable() && self.readable_callback_active {
            if let Some(ref mut callback) = self.readable_callback {
                self.readable_callback_active = false;
                callback();
            }
        }
    }

    /// remote window limit update received
    pub fn update_remote_limit(&mut self, limit: u64) -> bool {
        if limit > 0 {
            self.is_initial_window = false;
        }

        if limit > self.window_limit {
            self.window_limit = limit;
            self.notify_if_readable();
            true
        } else {
            false
        }
    }

    /// write segment to stream, bypassing all restrictions
    pub fn write_direct(&mut self, buf: &[u8]) -> Range<u64> {
        let base = self.buffer_offset + self.buffer.len() as u64;
        let segment = base..(base + buf.len() as u64);
        self.buffer.extend(buf);
        self.queued.insert_range(segment.clone());
        self.notify_if_readable();
        segment
    }

    /// write segment to stream, respecting window and buffer limit
    pub fn write_limited(&mut self, buf: &[u8]) -> usize {
        let writable = self.writable();
        if writable == 0 {
            0
        } else {
            let limit = usize::min(u64::min(usize::MAX as u64, writable) as usize, buf.len());
            self.write_direct(&buf[0..limit]);
            limit
        }
    }

    /// set message marker at offset
    pub fn set_message(&mut self, offset: u64) {
        if offset < self.buffer_offset {
            return;
        }

        self.message_offsets.insert(offset);
    }

    /// update deadline retransmission offset lower bound
    pub fn update_deadline(&mut self, new_limit: u64) {
        match self.retransmit_strategy {
            RetransmitStrategy::Deadline { ref mut limit } => {
                trace!(limit = new_limit, "update deadline");
                *limit = new_limit;
            }
            _ => panic!("stream not using deadline retransmission"),
        }
    }
}

#[cfg(test)]
pub mod test {
    use super::*;

    #[test]
    fn derpify() -> anyhow::Result<()> {
        tracing_subscriber::fmt::init();
        let mut outbound =
            StreamOutboundState::new(4096, RetransmitStrategy::Deadline { limit: 0 }, None, None);
        outbound.update_deadline(4);
        Ok(())
    }
}
