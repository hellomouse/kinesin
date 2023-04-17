//! Stream inbound implementation

use std::collections::BTreeMap;
use std::ops::Range;

use tracing::trace;

use crate::common::range_set::RangeSet;
use crate::common::ring_buffer::{RingBuf, RingBufSlice};

/// stream inbound buffer
pub struct StreamInboundState {
    /// buffer for received data
    pub buffer: RingBuf<u8>,
    /// stream offset at which buffer starts
    pub buffer_offset: u64,

    /// received segments
    pub received: RangeSet,
    /// offsets into the stream where messages begin, if applicable
    pub message_offsets: BTreeMap<u64, Option<u32>>,
    /// whether stream is operating in reliable mode
    pub is_reliable: bool,
    /// flow control limit
    pub window_limit: u64,
    /// final length of stream (offset of final byte + 1)
    pub final_offset: Option<u64>,
}

/// result enum of StreamInboundState::receive_segment
#[derive(PartialEq, Debug)]
pub enum ReceiveSegmentResult {
    /// some or all of the segment is new and has been processed
    Received,
    /// all of the segment has already been received
    Duplicate,
    /// segment exceeds window limit and stream state is inconsistent
    ExceedsWindow,
}

// Invariants:
// - `window_limit - buffer_offset <= isize::MAX` to ensure `buffer` remains
//   within capacity limits
// - `received` must contain the range 0..buffer_offset
// - `received` must not contain segments past `buffer_offset + buffer.len()`

impl StreamInboundState {
    /// create new instance
    pub fn new(initial_window_limit: u64, is_reliable: bool) -> StreamInboundState {
        assert!(
            initial_window_limit <= isize::MAX as u64,
            "initial window limit out of range"
        );
        StreamInboundState {
            buffer: RingBuf::new(),
            buffer_offset: 0,
            received: RangeSet::unlimited(),
            message_offsets: BTreeMap::new(),
            is_reliable,
            window_limit: initial_window_limit,
            final_offset: None,
        }
    }

    /// process incoming segment
    #[must_use = "must check if segment exceeds window limit"]
    pub fn receive_segment(&mut self, offset: u64, data: &[u8]) -> ReceiveSegmentResult {
        let tail = offset + data.len() as u64;
        if tail > self.window_limit {
            return ReceiveSegmentResult::ExceedsWindow;
        }

        let segment = offset..tail;
        if self.received.has_range(segment.clone()) {
            return ReceiveSegmentResult::Duplicate;
        }

        // ensure buffer is long enough
        let buffer_end: usize = (segment.end - self.buffer_offset)
            .try_into()
            .expect("window limit invalid");
        if buffer_end > self.buffer.len() {
            self.buffer.fill_at_back(buffer_end - self.buffer.len(), 0);
        }

        // copy new ranges
        for to_copy in self.received.range_complement(segment.clone()) {
            let len: usize = (to_copy.end - to_copy.start).try_into().unwrap();
            let buffer_index: usize = to_copy
                .start
                .checked_sub(self.buffer_offset)
                .expect("received set inconsistent with buffer")
                .try_into()
                .unwrap();

            let slice_start = (to_copy.start - offset) as usize;
            let data_slice = &data[slice_start..slice_start + len];
            trace!("copy {} bytes to offset {}", len, to_copy.start);
            self.buffer
                .range_mut(buffer_index..buffer_index + len)
                .copy_from_slice(data_slice);
        }

        self.received.insert_range(segment);

        ReceiveSegmentResult::Received
    }

    /// advance window limit
    pub fn set_limit(&mut self, new_limit: u64) {
        assert!(new_limit >= self.window_limit, "limit cannot go backwards");

        // ensure buffer size is within limits
        if new_limit - self.buffer_offset > isize::MAX as u64 {
            panic!("new window limit exceeds maximum buffer capaciity");
        }

        trace!(
            "advance window limit by {} bytes (window_limit = {})",
            new_limit - self.window_limit,
            new_limit
        );

        self.window_limit = new_limit;
    }

    /// set message marker at offset
    pub fn set_message_marker(&mut self, offset: u64) {
        if offset < self.buffer_offset {
            return;
        }

        trace!("message at offset {}", offset);
        self.message_offsets.insert(offset, None);
    }

    /// set final offset from sender
    pub fn set_final_offset(&mut self, offset: u64) -> bool {
        if self.final_offset.is_some() {
            false
        } else {
            self.final_offset = Some(offset);
            true
        }
    }

    /// advance buffer, discarding data lower than the new base offset
    pub fn advance_buffer(&mut self, new_base: u64) {
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

        // discard old message offsets
        if self.message_offsets.len() > 0 {
            self.message_offsets = self.message_offsets.split_off(&new_base);
        }

        // mark everything prior as received
        self.received.insert_range(0..new_base);
    }

    /// read segment from buffer, if available
    pub fn read_segment<'a>(&'a self, segment: Range<u64>) -> Option<RingBufSlice<'a, u8>> {
        let len: usize = segment
            .end
            .checked_sub(segment.start)
            .expect("range cannot be reverse")
            .try_into()
            .expect("range out of bounds");

        if !self.received.has_range(segment.clone()) {
            // requested segment not complete
            return None;
        }
        if segment.start < self.buffer_offset {
            // requested segment no longer present
            return None;
        }

        // checked by len calculation
        let start = (segment.start - self.buffer_offset) as usize;
        if start + len > self.buffer.len() {
            return None;
        }
        Some(self.buffer.range(start..start + len))
    }

    /// read available bytes from start of buffer
    ///
    /// Only really makes sense when `is_reliable = true`.
    pub fn read_next<'a>(&'a self, limit: usize) -> Option<RingBufSlice<'a, u8>> {
        let available = self.received.peek_first()?.end;
        debug_assert!(available >= self.buffer_offset);
        if self.buffer_offset == available {
            None
        } else {
            let len = u64::min(available, limit as u64) as usize;
            Some(self.buffer.range(0..len))
        }
    }

    /// check if stream is fully received
    ///
    /// If unreliable, will return true as soon as a final offset is received,
    /// even if more segments are in transit.
    pub fn finished(&self) -> bool {
        if let Some(final_offset) = self.final_offset {
            if !self.is_reliable {
                true
            } else {
                if let Some(received) = self.received.peek_first() {
                    received.end >= final_offset
                } else {
                    false
                }
            }
        } else {
            false
        }
    }
}

#[cfg(test)]
pub mod test {
    use crate::stream::inbound::ReceiveSegmentResult;

    use super::StreamInboundState;

    #[test]
    fn receive() {
        let mut inbound = StreamInboundState::new(4096, true);
        let hello = String::from("Hello, ");
        let world = String::from("world!");
        assert_eq!(
            inbound.receive_segment(hello.len() as u64, world.as_bytes()),
            ReceiveSegmentResult::Received
        );
        assert_eq!(
            inbound.receive_segment(0, hello.as_bytes()),
            ReceiveSegmentResult::Received
        );
        assert_eq!(
            inbound.receive_segment(8192, &[3, 4, 5, 6]),
            ReceiveSegmentResult::ExceedsWindow
        );
        assert_eq!(
            inbound.receive_segment(3, &[3]),
            ReceiveSegmentResult::Duplicate
        );
        assert!(inbound.set_final_offset((hello.len() + world.len()) as u64));
        let slice = inbound.read_next(64).unwrap();
        let mut read: Vec<u8> = Vec::with_capacity(slice.len());
        read.resize(slice.len(), 0);
        slice.copy_to_slice(&mut read);
        let hello2 = String::from_utf8(read).unwrap();
        assert_eq!(hello2, hello + &world);
        assert!(inbound.finished());
    }
}
