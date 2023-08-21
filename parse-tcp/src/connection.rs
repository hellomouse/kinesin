use tracing::{debug, trace, warn};
use uuid::Uuid;

use crate::flow_table::{Flow, FlowCompare};
use crate::stream::Stream;
use crate::TcpMeta;

/// TCP handshake state
#[derive(Debug)]
pub enum HandshakeState {
    /// not yet initialized
    None,
    /// SYN read, expect SYN/ACK
    SynSent {
        /// sequence number of initial SYN
        seq_no: u32,
    },
    /// SYN/ACK read, expect ACK
    SynReceived {
        /// sequence number of SYN/ACK
        seq_no: u32,
        /// acknowledgment number of SYN/ACK
        ack_no: u32,
        /// whether or not we saw the first SYN
        syn_seen: bool,
    },
    /// handshake complete, connection established
    Established {
        /// initial sequence number of forward direction
        forward_isn: u32,
        /// initial sequence number of reverse direction
        reverse_isn: u32,
    },
    /// TCP RST encountered
    Reset,
    /// graceful close
    Closed,
}

/// packet direction
pub enum Direction {
    /// forward direction: client -> server, assuming client is whoever sent the
    /// first SYN
    Forward,
    /// reverse direction: server -> client, assuming client is whoever sent the
    /// first SYN
    Reverse,
}

/// object representing TCP connection
pub struct Connection {
    /// unique identifier for connection
    pub uuid: Uuid,
    /// forward direction flow identifier
    pub forward_flow: Flow,
    /// state of connection handshake
    pub handshake_state: HandshakeState,

    /// whether the full 3-way handshake was observed
    pub observed_handshake: bool,
    /// whether the connection close was observed (either by FIN or RST)
    pub observed_close: bool,

    /// forward direction stream
    pub forward_stream: Stream,
    /// reverse direction stream
    pub reverse_stream: Stream,
    /// whether forward_stream is valid (false if window desynchronized)
    pub forward_stream_valid: bool,
    /// whether reverse_stream is valid
    pub reverse_stream_valid: bool,
}

/// result from Connection::handle_packet
pub enum HandlePacketResult {
    /// everything was fine, probably
    Fine,
}

impl Connection {
    /// create new connection with flow
    pub fn new(forward_flow: Flow) -> Connection {
        Connection {
            uuid: Uuid::new_v4(),
            forward_flow,
            handshake_state: HandshakeState::Closed,
            observed_handshake: false,
            observed_close: false,
            forward_stream: Stream::new(),
            forward_stream_valid: true,
            reverse_stream: Stream::new(),
            reverse_stream_valid: true,
        }
    }

    /// handle a packet supposedly belonging to this connection
    #[tracing::instrument(name = "conn", skip_all, fields(self.uuid))]
    pub fn handle_packet(&mut self, meta: TcpMeta, data: &[u8]) -> bool {
        debug_assert_ne!(self.forward_flow.compare_tcp_meta(&meta), FlowCompare::None);
        if meta.flags.syn {
            self.handle_syn(meta)
        } else if meta.flags.rst {
            self.handle_rst(meta)
        } else {
            // FIN packets handled here too, as they may carry data
            self.handle_data_packet(meta, data)
        }
    }

    /// handle packet with SYN flag
    pub fn handle_syn(&mut self, meta: TcpMeta) -> bool {
        debug_assert!(meta.flags.syn);
        if meta.flags.rst {
            // probably shouldn't happen
            warn!("received strange packet with flags {:?}", meta.flags);
        }
        match self.handshake_state {
            HandshakeState::None => {
                if meta.flags.ack {
                    // SYN/ACK
                    self.handshake_state = HandshakeState::SynReceived {
                        seq_no: meta.seq_number,
                        ack_no: meta.ack_number,
                        syn_seen: false,
                    };
                    trace!(
                        "handle_syn: got SYN/ACK (no SYN), None -> SynReceived (seq {}, ack {})",
                        meta.seq_number,
                        meta.ack_number
                    );
                    if let Some(scale) = meta.option_window_scale {
                        trace!("got window scale (SYN/ACK): {}", scale);
                        self.reverse_stream.window_scale = scale;
                    }
                    if self.forward_flow.compare_tcp_meta(&meta) == FlowCompare::Forward {
                        // SYN/ACK is expected server -> client
                        trace!("handle_syn: got SYN/ACK, reversing forward_flow");
                        self.forward_flow.reverse();
                    }
                    true
                } else {
                    // first SYN
                    self.handshake_state = HandshakeState::SynSent {
                        seq_no: meta.seq_number,
                    };
                    trace!(
                        "handle_syn: got SYN, None -> SynSent (seq {})",
                        meta.seq_number
                    );
                    if let Some(scale) = meta.option_window_scale {
                        trace!("got window scale (first SYN): {}", scale);
                        self.forward_stream.window_scale = scale;
                    }
                    if self.forward_flow.compare_tcp_meta(&meta) == FlowCompare::Reverse {
                        // SYN is expected client -> server
                        self.forward_flow.reverse();
                    }
                    true
                }
            }
            HandshakeState::SynSent { seq_no } => {
                // expect: SYN/ACK
                if meta.flags.ack {
                    // SYN/ACK received
                    if self.forward_flow.compare_tcp_meta(&meta) != FlowCompare::Reverse {
                        // wrong direction?
                        trace!("handle_syn: dropped SYN/ACK in wrong direction (state SynSent)");
                        false
                    } else {
                        if meta.ack_number != seq_no + 1 {
                            warn!(
                                "SYN/ACK packet ack number mismatch: expected {}, found {}",
                                seq_no + 1,
                                meta.ack_number
                            );
                        }
                        self.handshake_state = HandshakeState::SynReceived {
                            seq_no: meta.seq_number,
                            ack_no: meta.ack_number,
                            syn_seen: true,
                        };
                        trace!(
                            "handle_syn: received SYN/ACK, SynSent -> SynReceived (seq {}, ack {})",
                            meta.seq_number,
                            meta.ack_number
                        );
                        if let Some(scale) = meta.option_window_scale {
                            trace!("got window scale (SYN/ACK): {}", scale);
                            self.reverse_stream.window_scale = scale;
                        }
                        true
                    }
                } else {
                    // likely duplicate SYN
                    false
                }
            }
            HandshakeState::SynReceived { .. } => {
                // either duplicate SYN or SYN/ACK, ignore
                false
            }
            HandshakeState::Established { .. } => {
                // ???
                warn!("received SYN for established connection?");
                false
            }
            _ => false, // ignore
        }
    }

    /// handle packet with RST flag
    pub fn handle_rst(&mut self, meta: TcpMeta) -> bool {
        debug_assert!(meta.flags.rst);
        debug!("received RST");
        self.handshake_state = HandshakeState::Reset;
        self.observed_close = true;
        true
    }

    /// handle ordinary data packet
    pub fn handle_data_packet(&mut self, meta: TcpMeta, data: &[u8]) -> bool {
        match self.handshake_state {
            HandshakeState::None | HandshakeState::SynSent { .. } => {
                trace!("handle_data_packet: received data before handshake completion, {:?} -> Established", self.handshake_state);
                let (forward_isn, reverse_isn) = match self.forward_flow.compare_tcp_meta(&meta) {
                    FlowCompare::Forward => (meta.seq_number, meta.ack_number),
                    FlowCompare::Reverse => (meta.ack_number, meta.seq_number),
                    _ => unreachable!("got unrelated flow"),
                };

                self.handshake_state = HandshakeState::Established {
                    forward_isn,
                    reverse_isn,
                };

                self.forward_stream.set_isn(forward_isn);
                self.reverse_stream.set_isn(reverse_isn);
                true
            }
            HandshakeState::SynReceived {
                seq_no,
                ack_no,
                syn_seen,
            } => {
                let (forward_isn, reverse_isn) = match self.forward_flow.compare_tcp_meta(&meta) {
                    FlowCompare::Forward => {
                        if meta.flags.ack
                            && meta.seq_number == ack_no
                            && meta.ack_number == seq_no + 1
                        {
                            if syn_seen {
                                self.observed_handshake = true;
                                trace!("handle_data_packet: got complete handshake");
                            } else {
                                trace!("handle_data_packet: got SYN/ACK and ACK of handshake");
                            }
                        } else {
                            trace!("handle_data_packet: probably lost final packet of handshake")
                        }
                        (meta.seq_number, meta.ack_number)
                    }
                    FlowCompare::Reverse => {
                        trace!("handle_data_packet: received reverse direction packet instead of final handshake ACK");
                        (meta.ack_number, meta.seq_number)
                    }
                    _ => unreachable!("got unrelated flow"),
                };
                trace!(
                    "handle_data_packet: received data packet, SynReceived -> Established \
                    (forward_isn: {forward_isn}, reverse_isn: {reverse_isn})"
                );

                self.handshake_state = HandshakeState::Established {
                    forward_isn,
                    reverse_isn,
                };
                self.forward_stream.set_isn(forward_isn);
                self.reverse_stream.set_isn(reverse_isn);
                true
            }
            _ => {
                // established or (closed but more data)
                let (forward, reverse) = match self.forward_flow.compare_tcp_meta(&meta) {
                    FlowCompare::Forward => (&mut self.forward_stream, &mut self.reverse_stream),
                    FlowCompare::Reverse => (&mut self.reverse_stream, &mut self.forward_stream),
                    _ => unreachable!("got unrelated flow"),
                };

                let mut did_something = false;
                if !data.is_empty() {
                    did_something |= forward.handle_data_packet(meta.seq_number, data);
                }
                if meta.flags.ack {
                    did_something |= reverse.handle_ack_packet(meta.ack_number, meta.window);
                }
                if meta.flags.fin {
                    did_something |= forward.handle_fin_packet(meta.seq_number, data.len());
                }
                did_something
            }
        }
    }
}
