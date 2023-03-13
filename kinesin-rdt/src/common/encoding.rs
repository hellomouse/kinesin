/// determine how many bytes are required to encode a varint
pub fn varint_size(n: u64) -> Option<usize> {
    if n < 2u64.pow(8 - 2) {
        Some(1)
    } else if n < 2u64.pow(16 - 2) {
        Some(2)
    } else if n < 2u64.pow(32 - 2) {
        Some(4)
    } else if n < 2u64.pow(64 - 2) {
        Some(8)
    } else {
        None
    }
}

/// write varint to buffer, returning how many bytes were used
pub fn write_varint(buf: &mut [u8], n: u64) -> Option<usize> {
    if n < 2u64.pow(8 - 2) {
        let val = n as u8;
        buf[0] = val;
        Some(1)
    } else if n < 2u64.pow(16 - 2) {
        let mut val = n as u16;
        val |= 0b01u16 << (16 - 2);
        buf[..2].copy_from_slice(&val.to_be_bytes());
        Some(2)
    } else if n < 2u64.pow(32 - 2) {
        let mut val = n as u32;
        val |= 0b10u32 << (32 - 2);
        buf[..4].copy_from_slice(&val.to_be_bytes());
        Some(4)
    } else if n < 2u64.pow(64 - 2) {
        let mut val = n as u64;
        val |= 0b11u64 << (64 - 2);
        buf[..8].copy_from_slice(&val.to_be_bytes());
        Some(8)
    } else {
        None
    }
}

/// read varint from buffer, returning (value, size)
pub fn read_varint(buf: &mut [u8]) -> (u64, usize) {
    let length = buf[0] >> 6;
    match length {
        0 => {
            ((buf[0] & (u8::MAX >> 2)) as u64, 1)
        },
        1 => {
            let val = u16::from_be_bytes(buf[0..2].try_into().unwrap());
            ((val & (u16::MAX >> 2)) as u64, 2)
        },
        2 => {
            let val = u32::from_be_bytes(buf[0..4].try_into().unwrap());
            ((val & (u32::MAX >> 2)) as u64, 4)
        },
        3 => {
            let val = u64::from_be_bytes(buf[0..8].try_into().unwrap());
            (val & (u64::MAX >> 2), 8)
        },
        _ => unreachable!()
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn varint_test() {
        let mut buf = [0u8, 5, 5, 5, 5, 5, 5, 5];
        assert_eq!(varint_size(0), Some(1));
        assert_eq!(write_varint(&mut buf, 0), Some(1));
        assert_eq!(buf, [0u8, 5, 5, 5, 5, 5, 5, 5]);
        assert_eq!(read_varint(&mut buf), (0, 1));

        assert_eq!(varint_size(16), Some(1));
        assert_eq!(write_varint(&mut buf, 16), Some(1));
        assert_eq!(buf, [16u8, 5, 5, 5, 5, 5, 5, 5]);
        assert_eq!(read_varint(&mut buf), (16, 1));

        assert_eq!(varint_size(128), Some(2));
        assert_eq!(write_varint(&mut buf, 128), Some(2));
        assert_eq!(buf, [64u8, 128, 5, 5, 5, 5, 5, 5]);
        assert_eq!(read_varint(&mut buf), (128, 2));

        assert_eq!(varint_size(57_829_138), Some(4));
        assert_eq!(write_varint(&mut buf, 57_829_138), Some(4));
        assert_eq!(buf, [0x83u8, 0x72, 0x67, 0x12, 5, 5, 5, 5]);
        assert_eq!(read_varint(&mut buf), (57_829_138, 4));

        assert_eq!(varint_size(3_933_194_752_826_327_366), Some(8));
        assert_eq!(write_varint(&mut buf, 3_933_194_752_826_327_366), Some(8));
        assert_eq!(buf, [0xf6u8, 0x95, 0x83, 0xc9, 0xea, 0xa4, 0xc1, 0x46]);
        assert_eq!(read_varint(&mut buf), (3_933_194_752_826_327_366, 8));
    }
}
