/// determine how many bytes are required to encode a varint8
pub fn varint8_size(n: u64) -> Option<usize> {
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

/// write varint8 to buffer, returning how many bytes were used
pub fn write_varint8(buf: &mut [u8], n: u64) -> Option<usize> {
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
        let mut val = n;
        val |= 0b11u64 << (64 - 2);
        buf[..8].copy_from_slice(&val.to_be_bytes());
        Some(8)
    } else {
        None
    }
}

/// read varint8 from buffer, returning (value, size)
pub fn read_varint8(buf: &mut [u8]) -> (u64, usize) {
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

/// determine how many bytes are required to encode a varint8
pub fn varint4_size(n: u32) -> Option<usize> {
    if n < 2u32.pow(8 - 2) {
        Some(1)
    } else if n < 2u32.pow(16 - 2) {
        Some(2)
    } else if n < 2u32.pow(32 - 1) {
        Some(4)
    } else {
        None
    }
}

/// write varint4 to buffer, returning how many bytes were used
pub fn write_varint4(buf: &mut [u8], n: u32) -> Option<usize> {
    if n < 2u32.pow(8 - 2) {
        let val = n as u8;
        buf[0] = val;
        Some(1)
    } else if n < 2u32.pow(16 - 2) {
        let mut val = n as u16;
        val |= 0b01u16 << (16 - 2);
        buf[..2].copy_from_slice(&val.to_be_bytes());
        Some(2)
    } else if n < 2u32.pow(32 - 1) {
        let mut val = n;
        val |= 0b1u32 << (32 - 1);
        buf[..4].copy_from_slice(&val.to_be_bytes());
        Some(4)
    } else {
        None
    }
}

/// read varint4 from buffer, returning (value, size)
pub fn read_varint4(buf: &mut [u8]) -> (u32, usize) {
    let length = buf[0] >> 6;
    match length {
        0b00 => {
            ((buf[0] & (u8::MAX >> 2)) as u32, 1)
        },
        0b01 => {
            let val = u16::from_be_bytes(buf[0..2].try_into().unwrap());
            ((val & (u16::MAX >> 2)) as u32, 2)
        },
        0b10 | 0b11 => {
            let val = u32::from_be_bytes(buf[0..4].try_into().unwrap());
            (val & (u32::MAX >> 1), 4)
        },
        _ => unreachable!()
    }
}


#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn varint8_test() {
        let mut buf = [0u8, 5, 5, 5, 5, 5, 5, 5];
        assert_eq!(varint8_size(0), Some(1));
        assert_eq!(write_varint8(&mut buf, 0), Some(1));
        assert_eq!(buf, [0, 5, 5, 5, 5, 5, 5, 5]);
        assert_eq!(read_varint8(&mut buf), (0, 1));

        assert_eq!(varint8_size(16), Some(1));
        assert_eq!(write_varint8(&mut buf, 16), Some(1));
        assert_eq!(buf, [16, 5, 5, 5, 5, 5, 5, 5]);
        assert_eq!(read_varint8(&mut buf), (16, 1));

        assert_eq!(varint8_size(128), Some(2));
        assert_eq!(write_varint8(&mut buf, 128), Some(2));
        assert_eq!(buf, [64, 128, 5, 5, 5, 5, 5, 5]);
        assert_eq!(read_varint8(&mut buf), (128, 2));

        assert_eq!(varint8_size(57_829_138), Some(4));
        assert_eq!(write_varint8(&mut buf, 57_829_138), Some(4));
        assert_eq!(buf, [0x83, 0x72, 0x67, 0x12, 5, 5, 5, 5]);
        assert_eq!(read_varint8(&mut buf), (57_829_138, 4));

        assert_eq!(varint8_size(3_933_194_752_826_327_366), Some(8));
        assert_eq!(write_varint8(&mut buf, 3_933_194_752_826_327_366), Some(8));
        assert_eq!(buf, [0xf6, 0x95, 0x83, 0xc9, 0xea, 0xa4, 0xc1, 0x46]);
        assert_eq!(read_varint8(&mut buf), (3_933_194_752_826_327_366, 8));

        assert_eq!(varint8_size(9_000_000_000_000_000_000), None);
    }

    #[test]
    fn varint4_test() {
        let mut buf = [0u8, 5, 5, 5, 5, 5, 5, 5];
        assert_eq!(varint4_size(0), Some(1));
        assert_eq!(write_varint4(&mut buf, 0), Some(1));
        assert_eq!(buf, [0, 5, 5, 5, 5, 5, 5, 5]);
        assert_eq!(read_varint4(&mut buf), (0, 1));

        assert_eq!(varint4_size(16), Some(1));
        assert_eq!(write_varint4(&mut buf, 16), Some(1));
        assert_eq!(buf, [16, 5, 5, 5, 5, 5, 5, 5]);
        assert_eq!(read_varint4(&mut buf), (16, 1));

        assert_eq!(varint4_size(128), Some(2));
        assert_eq!(write_varint4(&mut buf, 128), Some(2));
        assert_eq!(buf, [64, 128, 5, 5, 5, 5, 5, 5]);
        assert_eq!(read_varint4(&mut buf), (128, 2));

        assert_eq!(varint4_size(57_829_138), Some(4));
        assert_eq!(write_varint4(&mut buf, 57_829_138), Some(4));
        assert_eq!(buf, [0x83, 0x72, 0x67, 0x12, 5, 5, 5, 5]);
        assert_eq!(read_varint4(&mut buf), (57_829_138, 4));

        assert_eq!(varint4_size(2_118_699_314), Some(4));
        assert_eq!(write_varint4(&mut buf, 2_118_699_314), Some(4));
        assert_eq!(buf, [0xfe, 0x48, 0xc9, 0x32, 5, 5, 5, 5]);
        assert_eq!(read_varint4(&mut buf), (2_118_699_314, 4));

        assert_eq!(varint4_size(2_147_483_648), None);
    }
}
