use kinesin_rdt::stream::inbound::{ReceiveSegmentResult, StreamInboundState};
use tracing::{debug, trace, warn};

/// size of the sequence number sliding window
const SEQ_WINDOW_SIZE: u32 = 1 << 30;
/// threshold for advancing the sequence number window
const SEQ_WINDOW_ADVANCE_THRESHOLD: u32 = 1 << 29;
/// how much to advance the sequence number window by
const SEQ_WINDOW_ADVANCE_BY: u32 = 1 << 28;
/// max accepted TCP window size
const MAX_ALLOWED_BUFFER_SIZE: u64 = 128 << 20; // MB

/// unidirectional stream of a connection
pub struct Stream {
    /// initial sequence number
    pub initial_sequence_number: u32,
    /// offset from packet sequence number to absolute stream offset
    pub seq_offset: u64,
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
    /// detected retransmission count
    pub retransmit_count: usize,
    /// count of bytes we do not have due to gaps
    pub gaps_length: u64,
}

impl Stream {
    /// create new instance
    pub fn new() -> Self {
        Stream {
            initial_sequence_number: 0,
            seq_offset: 0,
            window_scale: 0,
            state: StreamInboundState::new(0, true),
            seq_window_start: 0,
            seq_window_end: 0,
            highest_acked: 0,
            retransmit_count: 0,
            gaps_length: 0,
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

    /// set initial sequence number
    pub fn set_isn(&mut self, isn: u32) {
        self.initial_sequence_number = isn;
        self.seq_offset = isn as u64;
        self.state.advance_buffer(isn as u64);
        // set seq window to sane initial values
        self.seq_window_start = isn;
        self.seq_window_end = self.seq_window_start.wrapping_add(SEQ_WINDOW_SIZE);
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
                Some(self.seq_offset + number as u64)
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
            Some(self.seq_offset + number as u64)
        } else {
            // at low section of window
            let bytes_from_start = number.wrapping_sub(self.seq_window_start);
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
                    // update seq_offset after overflow
                    self.seq_offset += 1 << 32;
                    trace!("seq_window overflow over, advance seq_offset");
                }
            }
            // rollover not yet done
            Some(self.seq_offset + (1 << 32) + number as u64)
        }
    }

    /// handle data packet in the forward direction
    pub fn handle_data_packet(&mut self, sequence_number: u32, mut data: &[u8]) -> bool {
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
                    seq: {}, len: {}, original window limit: {}",
                sequence_number,
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
        match self.state.receive_segment(offset, data) {
            ReceiveSegmentResult::Duplicate => {
                // probably a retransmit
                self.retransmit_count += 1;
            }
            ReceiveSegmentResult::ExceedsWindow => {
                // should not happen, window limit is guarded
                unreachable!();
            }
            ReceiveSegmentResult::Received => {
                // all is well, probably
            }
        }

        true
    }

    /// handle ack packet in the reverse direction
    pub fn handle_ack_packet(&mut self, acknowledgment_number: u32, window_size: u16) -> bool {
        let Some(offset) = self.update_offset(acknowledgment_number) else {
            warn!(
                "received ack number {} outside of window ({} - {})",
                acknowledgment_number, self.seq_window_start, self.seq_window_end
            );
            return false;
        };

        // set expected window limit
        let limit = offset + ((window_size as u64) << (self.window_scale as u64));
        trace!(
            "handle_ack_packet: ack: {}, win: {}, absolute: {}",
            acknowledgment_number,
            window_size,
            limit
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

        self.highest_acked = offset;
        true
    }

    /// handle FIN packet
    pub fn handle_fin_packet(&mut self, sequence_number: u32, data_len: usize) -> bool {
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
            }
            Some(prev_fin) => {
                if fin_offset != prev_fin {
                    warn!(
                        "received duplicate FIN different from previous: prev: {}, now: {}",
                        prev_fin, fin_offset
                    );
                }
                // otherwise it is just retransmit
            }
        }
        true
    }
}

impl Default for Stream {
    fn default() -> Self {
        Self::new()
    }
}
