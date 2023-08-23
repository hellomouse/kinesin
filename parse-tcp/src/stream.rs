use std::collections::BinaryHeap;
use std::ops::Range;

use kinesin_rdt::common::ring_buffer::RingBufSlice;
use kinesin_rdt::stream::inbound::{ReceiveSegmentResult, StreamInboundState};
use tracing::{debug, trace, warn};

use crate::PacketExtra;

/// size of the sequence number sliding window
const SEQ_WINDOW_SIZE: u32 = 1024 << 20; // MB
/// threshold for advancing the sequence number window
const SEQ_WINDOW_ADVANCE_THRESHOLD: u32 = 512 << 20;
/// how much to advance the sequence number window by
const SEQ_WINDOW_ADVANCE_BY: u32 = 256 << 20;
/// max allowed size of stream buffer
const MAX_ALLOWED_BUFFER_SIZE: u64 = 128 << 20;
/// max size of segments_info in eleemnts
const MAX_SEGMENTS_INFO_COUNT: usize = 128 << 10;

// TODO: track segments so we can have metadata in a heap or something
/// unidirectional stream of a connection
pub struct Stream {
    /// initial sequence number
    pub initial_sequence_number: u32,
    /// offset from packet sequence number to absolute stream offset
    pub seq_offset: SeqOffset,
    /// window scale
    pub window_scale: u8,
    /// stream state
    pub state: StreamInboundState,
    /// lowest acceptable TCP sequence number (used to disambiguate absolute offset)
    pub seq_window_start: u32,
    /// highest acceptable TCP sequence number plus one
    pub seq_window_end: u32,
    /// highest offset at which we have received an ack
    pub highest_acked: u64,

    /// whether a reset happened in this direction
    pub had_reset: bool,
    /// true if the FIN for this stream was acked
    pub has_ended: bool,

    /// count of bytes skipped due to gaps
    pub gaps_length: u64,
    /// detected retransmission count
    pub retransmit_count: usize,
    /// segment metadata
    pub segments_info: BinaryHeap<SegmentInfo>,
    /// number of packets not written to segments_info because it was full
    pub segments_info_dropped: usize,
}

impl Stream {
    /// create new instance
    pub fn new() -> Self {
        Stream {
            initial_sequence_number: 0,
            seq_offset: SeqOffset::Initial(0),
            window_scale: 0,
            state: StreamInboundState::new(0, true),
            seq_window_start: 0,
            seq_window_end: 0,
            highest_acked: 0,
            had_reset: false,
            has_ended: false,
            gaps_length: 0,
            retransmit_count: 0,
            segments_info: BinaryHeap::new(),
            segments_info_dropped: 0,
        }
    }

    /// return the number of bytes currently buffered and readable
    pub fn readable_buffered_length(&self) -> usize {
        if let Some(highest_readable) = self.state.max_contiguous_offset() {
            (highest_readable - self.state.buffer_offset) as usize
        } else {
            0
        }
    }

    /// return the total length of the buffer, including segments not yet
    /// readable
    pub fn total_buffered_length(&self) -> usize {
        self.state.buffer.len()
    }

    /// get offset of head of internal buffer
    pub fn buffer_start(&self) -> u64 {
        self.state.buffer_offset
    }

    /// set the window scale option
    pub fn set_window_scale(&mut self, window_scale: u8) -> bool {
        if window_scale > 14 {
            // max value is 14
            warn!("rejected oversized window_scale value: {window_scale}");
            false
        } else {
            self.window_scale = window_scale;
            true
        }
    }

    /// set initial sequence number
    pub fn set_isn(&mut self, isn: u32, window_size: u16) {
        self.initial_sequence_number = isn;
        self.seq_offset = SeqOffset::Initial(isn);
        // set seq window to sane initial values
        self.seq_window_start = isn;
        self.seq_window_end = self.seq_window_start.wrapping_add(SEQ_WINDOW_SIZE);
        // update expected receive window
        let window_size = (window_size as u64) << self.window_scale as u64;
        if window_size < MAX_ALLOWED_BUFFER_SIZE {
            trace!("got initial window size from handshake: {window_size}");
            self.state.set_limit(window_size);
        } else {
            warn!("received window size in handshake is too large: {window_size}");
            self.state.set_limit(MAX_ALLOWED_BUFFER_SIZE);
        }
    }

    /// update seq_window and seq_offset based on current window, return whether
    /// the value was in the current window and the absolute stream offset
    pub fn update_offset(&mut self, number: u32) -> Option<u64> {
        // ensure in range
        if self.seq_window_start < self.seq_window_end {
            // does not wrap
            if !(number >= self.seq_window_start && number < self.seq_window_end) {
                None
            } else {
                if number - self.seq_window_start > SEQ_WINDOW_ADVANCE_THRESHOLD {
                    // advance window
                    let old_start = self.seq_window_start;
                    self.seq_window_start = number - SEQ_WINDOW_ADVANCE_BY;
                    self.seq_window_end = self.seq_window_start.wrapping_add(SEQ_WINDOW_SIZE);
                    trace!(
                        "advance seq_window {} -> {} (received seq {})",
                        old_start,
                        self.seq_window_start,
                        number
                    );
                }
                Some(self.seq_offset.compute_absolute(number))
            }
        } else if number < self.seq_window_start && number >= self.seq_window_end {
            // does wrap, out of range
            None
        } else if number >= self.seq_window_start {
            // at high section of window
            if number - self.seq_window_start > SEQ_WINDOW_ADVANCE_THRESHOLD {
                // advance window
                let old_start = self.seq_window_start;
                self.seq_window_start = number - SEQ_WINDOW_ADVANCE_BY;
                self.seq_window_end = self.seq_window_start.wrapping_add(SEQ_WINDOW_SIZE);
                trace!(
                    "advance seq_window {} -> {} (received seq {})",
                    old_start,
                    self.seq_window_start,
                    number
                );
            }
            Some(self.seq_offset.compute_absolute(number))
        } else {
            // at low section of window (sequence number has rolled over)
            let bytes_from_start = number.wrapping_sub(self.seq_window_start);
            // offset object to use for rolled over values
            let rollover_offset = match self.seq_offset {
                SeqOffset::Initial(isn) => SeqOffset::Subsequent((1 << 32) - isn as u64),
                SeqOffset::Subsequent(off) => SeqOffset::Subsequent(off + (1 << 32)),
            };
            if bytes_from_start > SEQ_WINDOW_ADVANCE_THRESHOLD {
                // advance window
                let old_start = self.seq_window_start;
                self.seq_window_start = number.wrapping_sub(SEQ_WINDOW_ADVANCE_BY);
                self.seq_window_end = self.seq_window_start.wrapping_add(SEQ_WINDOW_SIZE);
                trace!(
                    "advance seq_window {} -> {} (received seq {})",
                    old_start,
                    self.seq_window_start,
                    number
                );

                if self.seq_window_start < self.seq_window_end {
                    // seq_window rollover done, update seq_offset
                    self.seq_offset = rollover_offset.clone();
                    trace!("seq_window rollover over, advance seq_offset");
                }
            }
            let offset = rollover_offset.compute_absolute(number);
            Some(offset)
        }
    }

    /// handle data packet in the forward direction
    pub fn handle_data_packet(
        &mut self,
        sequence_number: u32,
        mut data: &[u8],
        extra: PacketExtra,
    ) -> bool {
        let Some(offset) = self.update_offset(sequence_number) else {
            warn!(
                "received seq number {} outside of window ({} - {})",
                sequence_number, self.seq_window_start, self.seq_window_end
            );
            return false;
        };

        let packet_end_offset = offset + data.len() as u64;
        if packet_end_offset > self.state.window_limit {
            // might have lost a packet or never got window_scale
            debug!(
                "got packet exceeding the original receiver's window limit: \
                    seq: {}, offset: {}, len: {}, original window limit: {}",
                sequence_number,
                offset,
                data.len(),
                self.state.window_limit
            );
            // try to extend the window limit
            if packet_end_offset - self.state.buffer_offset < MAX_ALLOWED_BUFFER_SIZE {
                trace!("extending window limit due to out-of-window packet");
                self.state.set_limit(packet_end_offset);
            } else {
                let max_offset = self.state.buffer_offset + MAX_ALLOWED_BUFFER_SIZE;
                let max_len = max_offset.saturating_sub(offset) as usize;
                if max_len > 0 {
                    warn!(
                        "packet exceeds max buffer, dropping {} bytes",
                        data.len() - max_len
                    );
                    data = &data[..max_len];
                } else {
                    warn!("packet exceeds max buffer, dropping packet");
                    return false;
                }
            }
        }

        // read in the packet
        let mut is_retransmit = false;
        match self.state.receive_segment(offset, data) {
            ReceiveSegmentResult::Duplicate => {
                // probably a retransmit
                self.retransmit_count += 1;
                is_retransmit = true;
                trace!(
                    "handle_data_packet: got retransmit of {} bytes at seq {}, offset {}",
                    data.len(),
                    sequence_number,
                    offset
                );
            }
            ReceiveSegmentResult::ExceedsWindow => {
                // should not happen, window limit is guarded
                unreachable!();
            }
            ReceiveSegmentResult::Received => {
                // all is well, probably
                trace!(
                    "handle_data_packet: got {} bytes at seq {}, offset {}",
                    data.len(),
                    sequence_number,
                    offset
                );
            }
        }

        self.add_segment_info(SegmentInfo {
            offset,
            extra,
            data: SegmentType::Data {
                len: data.len(),
                is_retransmit,
            },
        });

        true
    }

    /// handle ack packet in the reverse direction
    pub fn handle_ack_packet(
        &mut self,
        acknowledgment_number: u32,
        window_size: u16,
        extra: PacketExtra,
    ) -> bool {
        let Some(offset) = self.update_offset(acknowledgment_number) else {
            warn!(
                "received ack number {} outside of window ({} - {})",
                acknowledgment_number, self.seq_window_start, self.seq_window_end
            );
            return false;
        };

        if offset > self.highest_acked {
            self.highest_acked = offset;
            trace!("handle_ack_packet: highest ack is {offset}");
        }

        if let Some(final_seq) = self.state.final_offset {
            // check if final data packet was acked
            if self.highest_acked >= final_seq {
                self.has_ended = true;
                trace!("handle_ack_packet: fin (offset {final_seq}) got ack (offset {offset})");
            }
        }

        // set expected window limit
        let real_window = (window_size as u32) << (self.window_scale as u32);
        let limit = offset + real_window as u64;
        trace!(
            "handle_ack_packet: ack: {}, offset {}, win {}",
            acknowledgment_number,
            offset,
            real_window
        );

        if limit > self.state.window_limit {
            let new_buffer_size = limit - self.state.buffer_offset;
            if new_buffer_size > MAX_ALLOWED_BUFFER_SIZE {
                // would make buffer too large, either window too large (DoS?)
                // or the buffer is not getting drained properly
                warn!(
                    "received ack packet which would result in a buffer size \
                        exceeding the maximum allowed buffer size: \
                        ack: {}, win: {}, win scale: {}, absolute window limit: {}",
                    acknowledgment_number, window_size, self.window_scale, limit
                );
                self.state
                    .set_limit(self.state.buffer_offset + MAX_ALLOWED_BUFFER_SIZE);
            } else {
                self.state.set_limit(limit);
            }
        }

        self.add_segment_info(SegmentInfo {
            offset,
            extra,
            data: SegmentType::Ack {
                window: real_window as usize,
            },
        });

        true
    }

    /// handle FIN packet
    pub fn handle_fin_packet(
        &mut self,
        sequence_number: u32,
        data_len: usize,
        extra: PacketExtra,
    ) -> bool {
        let Some(offset) = self.update_offset(sequence_number) else {
            warn!(
                "received fin with seq number {} outside of window ({} - {})",
                sequence_number, self.seq_window_start, self.seq_window_end
            );
            return false;
        };
        let fin_offset = offset + data_len as u64;

        match self.state.final_offset {
            None => {
                self.state.set_final_offset(fin_offset);
                trace!(
                    "handle_fin_packet: seq: {}, len: {}, final offset: {}",
                    sequence_number,
                    data_len,
                    fin_offset
                );
            }
            Some(prev_fin) => {
                if fin_offset != prev_fin {
                    warn!(
                        "received duplicate FIN different from previous: prev: {}, now: {}",
                        prev_fin, fin_offset
                    );
                }
                trace!("handle_fin_packet: detected retransmitted FIN");
                // otherwise it is just retransmit
            }
        }

        self.add_segment_info(SegmentInfo {
            offset,
            extra,
            data: SegmentType::Fin {
                end_offset: fin_offset,
            },
        });
        true
    }

    /// add an info object to segments_info
    pub fn add_segment_info(&mut self, info: SegmentInfo) -> bool {
        if self.segments_info.len() < MAX_SEGMENTS_INFO_COUNT {
            self.segments_info.push(info);
            true
        } else {
            self.segments_info_dropped += 1;
            false
        }
    }

    /// pop and read segment info until offset, adding to vec
    pub fn read_segments_until(&mut self, end_offset: u64, in_segments: &mut Vec<SegmentInfo>) {
        loop {
            let Some(info_peek) = self.segments_info.peek() else {
                break;
            };
            if info_peek.offset >= end_offset {
                break;
            }

            in_segments.push(self.segments_info.pop().unwrap());
        }
    }

    /// read gaps in buffer in a given range, adding to vec and accounting in gaps_length
    pub fn read_gaps(&mut self, range: Range<u64>, in_gaps: &mut Vec<Range<u64>>) {
        for gap in self.state.received.range_complement(range) {
            trace!("read_gaps: gap: {} .. {}", gap.start, gap.end);
            in_gaps.push(gap.clone());
            self.gaps_length += gap.end - gap.start;
        }
    }

    /// read state until offset
    pub fn read_next(
        &mut self,
        end_offset: u64,
        in_segments: &mut Vec<SegmentInfo>,
        in_gaps: &mut Vec<Range<u64>>,
        read_fn: impl FnOnce(RingBufSlice<'_, u8>),
    ) -> bool {
        let start_offset = self.state.buffer_offset;
        if end_offset < start_offset {
            warn!("requested read of range that no longer exists");
            return false;
        }
        if end_offset == start_offset {
            // don't return zero-length reads
            return false;
        }
        if (end_offset - start_offset) as usize > self.state.buffer.len() {
            warn!("requested read of range past end of buffer");
            return false;
        }
        self.read_segments_until(end_offset, in_segments);
        self.read_gaps(start_offset..end_offset, in_gaps);
        // assume gaps don't exist
        self.state.received.insert_range(start_offset..end_offset);
        // acquire slice
        let Some(slice) = self.state.read_segment(start_offset..end_offset) else {
            panic!("InboundStreamState says range is not available");
        };
        read_fn(slice);
        // advance backing buffer
        self.state.advance_buffer(end_offset);
        true
    }
}

impl Default for Stream {
    fn default() -> Self {
        Self::new()
    }
}

/// information on each segment received
pub struct SegmentInfo {
    pub offset: u64,
    pub extra: PacketExtra,
    pub data: SegmentType,
}

/// type-specific information for each segment
pub enum SegmentType {
    Data { len: usize, is_retransmit: bool },
    Ack { window: usize },
    Fin { end_offset: u64 },
}

impl Ord for SegmentInfo {
    /// reversed compare of offset (we want pop to get the smallest offset)
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        match self.offset.cmp(&other.offset) {
            std::cmp::Ordering::Less => std::cmp::Ordering::Greater,
            std::cmp::Ordering::Equal => std::cmp::Ordering::Equal,
            std::cmp::Ordering::Greater => std::cmp::Ordering::Less,
        }
    }
}

impl PartialOrd for SegmentInfo {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for SegmentInfo {
    fn eq(&self, other: &Self) -> bool {
        self.offset == other.offset
    }
}

impl Eq for SegmentInfo {}

/// represents offset from packet sequence number to absolute offset
#[derive(Clone)]
pub enum SeqOffset {
    /// negative offset due to initial sequence number
    Initial(u32),
    /// positive offset after rollover
    Subsequent(u64),
}

impl SeqOffset {
    pub fn compute_absolute(&self, number: u32) -> u64 {
        match self {
            SeqOffset::Initial(isn) => {
                debug_assert!(number >= *isn);
                (number - isn) as u64
            }
            SeqOffset::Subsequent(offset) => number as u64 + offset,
        }
    }
}
