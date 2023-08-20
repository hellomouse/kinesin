use crate::flow_table::FlowId;
use crate::stream::Stream;

/// TCP handshake state
pub enum HandshakeState {
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
    /// forward direction flow identifier
    pub forward_flow_id: FlowId,
    /// state of connection handshake
    pub handshake_state: HandshakeState,
    
    /// forward direction stream
    pub forward_stream: Stream,
    /// reverse direction stream
    pub reverse_stream: Stream,
    /// whether forward_stream is valid (false if window desynchronized)
    pub forward_stream_valid: bool,
    /// whether reverse_stream is avlid
    pub reverse_stream_valid: bool,
}
