pub mod encoding;
pub mod stream;
pub mod buffer_util;

pub use stream::*;

// TODO: helpers for serialization, maybe macros?
// TODO: graceful error handling for too-short reads

/// frame serialization
pub trait Serialize {
    /// determine serialized length of frame
    fn serialized_length(&self) -> usize;
    /// write frame to buffer, returning serialized length
    fn write(&self, buf: &mut [u8]) -> usize;
    /// read frame from buffer, returning frame and serialized length
    fn read(buf: &[u8]) -> Result<(usize, Self), ()>
    where
        Self: Sized;

    /// whether the frame has special "serialize to end" behavior
    fn has_end_optimization() -> bool
    where
        Self: Sized,
    {
        false
    }
}

/// frame serialization allowing optimizations for end-of-packet frames
pub trait SerializeToEnd: Serialize {
    /// determine serialized length of frame at the end of the packet
    fn serialized_length_at_end(&self) -> usize {
        self.serialized_length()
    }

    /// write last frame of packet to buffer, returning serialized length
    fn write_to_end(&self, buf: &mut [u8]) -> usize {
        self.write(buf)
    }

    /// read last frame of packet from buffer, returning frame
    fn read_to_end(buf: &[u8]) -> Result<Self, ()>
    where
        Self: Sized,
    {
        Self::read(buf).map(|r| r.1)
    }

    /// whether the frame has special "serialize to end" behavior
    fn has_end_optimization() -> bool
    where
        Self: Sized,
    {
        true
    }
}
