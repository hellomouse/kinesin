use crate::flow_table::FlowId;
use crate::stream::Stream;

/// TCP handshake state
pub enum HandshakeState {
    /// SYN read, expect SYN/ACK
    SynSent,
    /// SYN/ACK read, expect ACK
    SynReceived,
    /// handshake complete, connection established
    Established,
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
}
