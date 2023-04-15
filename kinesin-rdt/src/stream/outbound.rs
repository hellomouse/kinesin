//! Stream outbound implementation

use std::collections::BTreeSet;
use std::ops::Range;

use tracing::trace;

use crate::common::range_set::RangeSet;
use crate::common::ring_buffer::{RingBuf, RingBufSlice};

pub enum RetransmitStrategy {
    Reliable,
    Unreliable,
    Deadline { limit: u64 },
}

/// default outbound buffer size limit
pub const OUTBOUND_BUFFER_DEFAULT_LIMIT: usize = 64 * 1024 * 1024;

/// stream outbound delivery
pub struct StreamOutboundState {
    /// buffer for outbound data
    pub buffer: RingBuf<u8>,
    /// stream offset at which buffer starts
    pub buffer_offset: u64,
    /// outbound buffer size limit
    pub buffer_limit: usize,

    /// segments queued for (re)transmission
    pub queued: RangeSet,
    /// segments successfully delivered (retransmission unnecessary)
    pub delivered: RangeSet,
    /// offsets into the stream where messages begin, if applicable
    pub message_offsets: BTreeSet<u64>,

    /// if we're still in the initial state (window limit not received yet)
    pub is_initial_window: bool,
    /// peer inbound flow control receive limit
    pub window_limit: u64,
    /// retransmission strategy on packet loss
    ///
    /// It is not currently supported to change this after construction.
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

// Invariants:
// - field `delivered` must always contain the range 0..buffer_offset

impl StreamOutboundState {
    pub fn new(
        initial_window_limit: u64,
        retransmit_strategy: RetransmitStrategy,
        writable_callback: Option<Box<dyn FnMut()>>,
        readable_callback: Option<Box<dyn FnMut()>>,
    ) -> StreamOutboundState {
        StreamOutboundState {
            buffer: RingBuf::new(),
            buffer_offset: 0,
            buffer_limit: OUTBOUND_BUFFER_DEFAULT_LIMIT,
            queued: RangeSet::unlimited(),
            delivered: RangeSet::unlimited(),
            message_offsets: BTreeSet::new(),
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
        let real_limit = u64::min(rwnd_limit, self.buffer_limit as u64);
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
            trace!(limit, "window advanced");
            self.window_limit = limit;
            self.notify_if_writable();
            true
        } else {
            false
        }
    }

    /// write segment to stream, bypassing all restrictions
    pub fn write_direct(&mut self, buf: &[u8]) -> Range<u64> {
        let base = self.buffer_offset + self.buffer.len() as u64;
        let segment = base..(base + buf.len() as u64);
        self.buffer.push_back_copy_from_slice(buf);
        self.queued.insert_range(segment.clone());
        self.notify_if_readable();
        trace!("write {} bytes at offset {}", base, buf.len());
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
    pub fn set_message_marker(&mut self, offset: u64) {
        if offset < self.buffer_offset {
            return;
        }

        trace!("message at offset {}", offset);
        self.message_offsets.insert(offset);
    }

    /// update deadline retransmission offset lower bound
    pub fn update_deadline(&mut self, new_limit: u64) {
        match self.retransmit_strategy {
            RetransmitStrategy::Deadline { ref mut limit } => {
                trace!(limit = new_limit, "update deadline");
                *limit = new_limit;
                // mark everything prior as delivered
                self.delivered.insert_range(0..new_limit);
            }
            _ => panic!("stream not using deadline retransmission"),
        }
    }

    /// advance buffer, discarding data lower than the new base
    pub fn advance_buffer(&mut self, new_base: u64) {
        // TODO: this might be a lot of code to be in a hot path
        if new_base < self.buffer_offset {
            panic!("cannot advance buffer backwards");
        }

        let delta = new_base - self.buffer_offset;
        if delta == 0 {
            return;
        }

        // shift buffer forward
        if (self.buffer.len() as u64) < delta {
            self.buffer.clear();
        } else {
            // cast safety: checked by branch
            self.buffer.drain(..(delta as usize));
        }
        self.buffer_offset += delta;

        trace!(delta, "advance buffer");

        // remove no longer relevant ranges
        self.queued.remove_range(..new_base);
        if self.message_offsets.len() > 0 {
            self.message_offsets = self.message_offsets.split_off(&new_base);
        }

        // mark everything prior as delivered
        self.delivered.insert_range(0..new_base);
    }

    /// advance buffer if necessary
    pub fn try_advance_buffer(&mut self) {
        let Some(first_delivered) = self.delivered.peek_first() else {
            return;
        };

        if first_delivered.end > self.buffer_offset {
            self.advance_buffer(first_delivered.end);
        }
    }

    /// get next queued segment
    pub fn next_segment(&mut self, data_size_limit: usize) -> Option<Range<u64>> {
        let mut next_queued = self.queued.peek_first()?;
        if let RetransmitStrategy::Deadline { limit } = self.retransmit_strategy {
            // dequeue everything before limit
            if next_queued.start < limit {
                self.queued.remove_range(..limit);
                next_queued = self.queued.peek_first()?;
            }
        }
        let start = next_queued.start;
        let len = u64::min(next_queued.end, data_size_limit as u64);
        Some(start..start + len)
    }

    /// get reference to bytes in segment, or none if out of range
    ///
    /// Will return slice and first message marker in range, if one exists.
    pub fn read_segment<'a>(
        &'a self,
        segment: Range<u64>,
    ) -> Option<(RingBufSlice<'a, u8>, Option<u64>)> {
        let buf_start: usize = segment
            .start
            .checked_sub(self.buffer_offset)?
            .try_into()
            .ok()?;
        let buf_end: usize = segment
            .end
            .checked_sub(self.buffer_offset)?
            .try_into()
            .ok()?;
        if buf_start > buf_end {
            return None;
        }
        if buf_end >= self.buffer.len() {
            return None;
        }
        let first_marker = self.message_offsets.range(segment).next().map(|r| *r);
        Some((self.buffer.range(buf_start..buf_end), first_marker))
    }

    /// mark segment as sent
    pub fn segment_sent(&mut self, segment: Range<u64>) {
        self.queued.remove_range(segment.clone());
        if matches!(self.retransmit_strategy, RetransmitStrategy::Unreliable) {
            // no need to retransmit segments
            self.delivered.insert_range(segment.clone());
        }
    }

    /// mark segment as lost
    pub fn segment_lost(&mut self, segment: Range<u64>) {
        for to_queue in self.delivered.range_complement(segment) {
            self.queued.insert_range(to_queue);
        }
    }

    /// mark segment as delivered
    pub fn segment_delivered(&mut self, segment: Range<u64>) {
        self.queued.remove_range(segment.clone());
        self.delivered.insert_range(segment);
    }
}

#[cfg(test)]
pub mod test {
    use std::cell::Cell;
    use std::rc::Rc;

    use super::*;

    #[test]
    fn emit_segment() {
        tracing_subscriber::fmt::init();

        let did_writable = Rc::new(Cell::new(false));
        let did_readable = Rc::new(Cell::new(false));
        let mut outbound = StreamOutboundState::new(
            0,
            RetransmitStrategy::Reliable,
            Some(Box::new({
                let cell = did_writable.clone();
                move || cell.set(true)
            })),
            Some(Box::new({
                let cell = did_readable.clone();
                move || cell.set(true)
            })),
        );

        outbound.writable_callback_active = true;
        outbound.update_remote_limit(4096);
        assert_eq!(did_writable.get(), true);
        did_writable.set(false);

        assert_eq!(outbound.writable(), 4096);
        outbound.readable_callback_active = true;
        outbound.write_direct(&[5u8; 64]);
        assert_eq!(did_readable.get(), true);
        did_readable.set(false);

        let segment = outbound.next_segment(4096).unwrap();
        assert_eq!(segment, 0..64);

        let segment = outbound.next_segment(8).unwrap();
        assert_eq!(segment, 0..8);
        outbound.segment_sent(segment.clone());
        let mut data = [0u8; 8];
        let slice = outbound.read_segment(segment.clone()).unwrap();
        slice.0.copy_to_slice(&mut data);
        assert_eq!(data, [5u8; 8]);

        let segment_2 = outbound.next_segment(8).unwrap();
        assert_eq!(segment_2, 8..16);
        outbound.segment_sent(segment_2.clone());
        outbound.segment_delivered(segment_2);

        outbound.segment_lost(segment.clone());
        assert_eq!(outbound.next_segment(4096).unwrap(), 0..8);
    }
}
