use kinesin_rdt::stream::inbound::StreamInboundState;

/// unidirectional stream of a connection
pub struct Stream {
    /// initial sequence number
    pub initial_sequence_number: u64,
    /// offset from packet sequence number to absolute stream offset
    pub seq_offset: u64,
    /// stream state
    pub state: StreamInboundState,
    // TODO: counters
}

impl Stream {
    /// create new instance
    pub fn new() -> Self {
        Stream {
            initial_sequence_number: 0,
            seq_offset: 0,
            state: StreamInboundState::new(0, true),
        }
    }

    /// set initial sequence number
    pub fn set_isn(&mut self, isn: u64) {
        self.initial_sequence_number = isn;
        self.seq_offset = isn;
        self.state.advance_buffer(isn);
    }
}
