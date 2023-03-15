//! Utility functions for testing

/// Vec-like that can be initialized with zeroes
pub trait Zeroed {
    /// create and initialize array of given length with zeroes
    fn zeroed(length: usize) -> Self;
}

impl Zeroed for Vec<u8> {
    fn zeroed(length: usize) -> Self {
        let mut vec = Vec::with_capacity(length);
        vec.resize(length, 0);
        vec
    }
}
