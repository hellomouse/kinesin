//! Frame types for streams

use super::encoding::{read_varint8, varint8_size, write_varint8};
use super::{Serialize, SerializeToEnd};

/// stream data frame
pub struct StreamData {
    /// stream identifier
    pub stream_id: u64,
    /// offset into stream
    pub stream_offset: u64,
    /// message start as offset into segment
    pub message_offset: Option<u16>,
    /// segment data
    pub data: Vec<u8>,
}

impl Serialize for StreamData {
    fn serialized_length(&self) -> usize {
        1 + varint8_size(self.stream_id).expect("stream id out of bounds")
            + varint8_size(self.stream_offset).expect("stream offset out of bounds")
            + if self.message_offset.is_some() { 2 } else { 0 }
            + 2
            + self.data.len()
    }

    fn write(&self, buf: &mut [u8]) -> usize {
        let mut index = 0usize;
        let mut flags = 0u8;
        if self.message_offset.is_some() {
            flags |= 1;
        }
        buf[index] = flags;
        index += 1;
        index += write_varint8(&mut buf[index..], self.stream_id).expect("stream id out of bounds");
        index += write_varint8(&mut buf[index..], self.stream_offset)
            .expect("stream offset out of bounds");
        let length: u16 = self
            .data
            .len()
            .try_into()
            .expect("stream data length invalid");
        buf[index..index + 2].copy_from_slice(&length.to_be_bytes());
        index += 2;
        if let Some(message_offset) = self.message_offset {
            buf[index..index + 2].copy_from_slice(&message_offset.to_be_bytes());
            index += 2;
        }
        buf[index..index + length as usize].copy_from_slice(&self.data);
        index + length as usize
    }

    fn read(buf: &[u8]) -> Result<(usize, Self), ()> {
        let mut index = 0usize;
        let flags = buf[index];
        index += 1;
        let has_message_offset = flags & 1 > 0;
        let (stream_id, len) = read_varint8(&buf[index..])?;
        index += len;
        let (stream_offset, len) = read_varint8(&buf[index..])?;
        index += len;
        let data_length = u16::from_be_bytes(buf[index..index + 2].try_into().unwrap());
        index += 2;
        let message_offset = if has_message_offset {
            let offset = u16::from_be_bytes(buf[index..index + 2].try_into().unwrap());
            index += 2;
            Some(offset)
        } else {
            None
        };
        let mut data = Vec::with_capacity(data_length as usize);
        data.extend_from_slice(&buf[index..index + data_length as usize]);
        index += data_length as usize;
        let frame = StreamData {
            stream_id,
            stream_offset,
            message_offset,
            data,
        };
        Ok((index, frame))
    }
}

impl SerializeToEnd for StreamData {
    fn serialized_length_at_end(&self) -> usize {
        1 + varint8_size(self.stream_id).expect("stream id out of bounds")
            + varint8_size(self.stream_offset).expect("stream offset out of bounds")
            + if self.message_offset.is_some() { 2 } else { 0 }
            + self.data.len()
    }

    fn write_to_end(&self, buf: &mut [u8]) -> usize {
        let mut index = 0usize;
        let mut flags = 0u8;
        if self.message_offset.is_some() {
            flags |= 1;
        }
        buf[index] = flags;
        index += 1;
        index += write_varint8(&mut buf[index..], self.stream_id).expect("stream id out of bounds");
        index += write_varint8(&mut buf[index..], self.stream_offset)
            .expect("stream offset out of bounds");
        if let Some(message_offset) = self.message_offset {
            buf[index..index + 2].copy_from_slice(&message_offset.to_be_bytes());
            index += 2;
        }
        buf[index..index + self.data.len()].copy_from_slice(&self.data);
        index + self.data.len()
    }

    fn read_to_end(buf: &[u8]) -> Result<Self, ()> {
        let mut index = 0usize;
        let flags = buf[index];
        index += 1;
        let has_message_offset = flags & 1 > 0;
        let (stream_id, len) = read_varint8(&buf[index..])?;
        index += len;
        let (stream_offset, len) = read_varint8(&buf[index..])?;
        index += len;
        let message_offset = if has_message_offset {
            let offset = u16::from_be_bytes(buf[index..index + 2].try_into().unwrap());
            index += 2;
            Some(offset)
        } else {
            None
        };
        let mut data = Vec::with_capacity(buf.len() - index);
        data.extend_from_slice(&buf[index..]);
        let frame = StreamData {
            stream_id,
            stream_offset,
            message_offset,
            data,
        };
        Ok(frame)
    }
}

/// stream window limit
pub struct StreamWindowLimit {
    /// stream identifier
    pub stream_id: u64,
    /// new limit
    pub limit: u64,
}

impl Serialize for StreamWindowLimit {
    fn serialized_length(&self) -> usize {
        varint8_size(self.stream_id).expect("stream id out of bounds")
            + varint8_size(self.limit).expect("limit out of bounds")
    }

    fn write(&self, buf: &mut [u8]) -> usize {
        let mut index = 0;
        index += write_varint8(&mut buf[index..], self.stream_id).expect("stream id out of bounds");
        index += write_varint8(&mut buf[index..], self.limit).expect("limit out of bounds");
        index
    }

    fn read(buf: &[u8]) -> Result<(usize, Self), ()> {
        let mut index = 0;
        let (stream_id, len) = read_varint8(&buf[index..])?;
        index += len;
        let (limit, len) = read_varint8(&buf[index..])?;
        index += len;
        let frame = StreamWindowLimit { stream_id, limit };
        Ok((index, frame))
    }
}

#[cfg(test)]
mod test {
    use crate::common::test_util::Zeroed;

    use super::*;
    #[test]
    fn stream_data() {
        let frame = StreamData {
            stream_id: 16384,
            stream_offset: 32768,
            message_offset: Some(4),
            data: vec![0, 1, 1, 2, 3, 5, 7, 12, 19, 31],
        };
        let length = frame.serialized_length();
        let mut buf = Vec::zeroed(length);
        assert_eq!(frame.write(&mut buf), length);
        let (length2, frame2) = StreamData::read(&buf).unwrap();
        assert_eq!(length, length2);
        assert_eq!(frame.stream_id, frame2.stream_id);
        assert_eq!(frame.stream_offset, frame2.stream_offset);
        assert_eq!(frame.message_offset, frame2.message_offset);
        assert_eq!(frame.data, frame2.data);
    }

    #[test]
    fn stream_limit() {
        let frame = StreamWindowLimit {
            stream_id: 38174897,
            limit: 993989418939
        };
        let length = frame.serialized_length();
        let mut buf = Vec::zeroed(length);
        assert_eq!(frame.write(&mut buf), length);
        let (length2, frame2) = StreamWindowLimit::read(&buf).unwrap();
        assert_eq!(length, length2);
        assert_eq!(frame.stream_id, frame2.stream_id);
        assert_eq!(frame.limit, frame2.limit);
    }
}
