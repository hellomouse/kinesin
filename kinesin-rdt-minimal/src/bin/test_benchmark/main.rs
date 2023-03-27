#![feature(test)]
extern crate test;

fn main() {
    println!("nothing here");
}

#[cfg(test)]
mod bench {
    use std::collections::VecDeque;

    use kinesin_rdt::common::ring_buffer::RingBuf;
    use test::{black_box, Bencher};

    const BLOCK_SIZE: usize = 4096;

    #[bench]
    fn vecdeque_write(bencher: &mut Bencher) {
        let mut deque: VecDeque<u8> = VecDeque::new();
        deque.extend(&[6u8; BLOCK_SIZE * 4]);
        bencher.iter(|| {
            let write_buf = black_box(Box::new([5u8; BLOCK_SIZE]));
            let deque_iter = deque.range_mut(4096..8192);
            assert!(deque_iter.len() == write_buf.len());
            for (i, v) in deque_iter.enumerate() {
                *v = write_buf[i];
            }
            let mut read_buf = black_box(Box::new([0u8; BLOCK_SIZE]));
            let deque_iter = deque.range(4096..8192);
            assert!(deque_iter.len() == read_buf.len());
            for (i, v) in deque_iter.enumerate() {
                read_buf[i] = *v;
            }
            black_box(read_buf);
        });
    }

    #[bench]
    fn local_write(bencher: &mut Bencher) {
        let mut buf: RingBuf<u8> = RingBuf::new();
        buf.push_back_copy_from_slice(&[6u8; BLOCK_SIZE * 4]);
        bencher.iter(|| {
            let write_buf = black_box(Box::new([5u8; BLOCK_SIZE]));
            buf.range_mut(4096..8192).copy_from_slice(&*write_buf);
            let mut read_buf = black_box(Box::new([0u8; BLOCK_SIZE]));
            buf.range(4096..8192).copy_to_slice(&mut *read_buf);
            black_box(read_buf);
        });
    }

    #[bench]
    fn extend(bencher: &mut Bencher) {
        let mut deque: VecDeque<u8> = VecDeque::new();
        bencher.iter(|| {
            deque.resize(BLOCK_SIZE, 0);
            black_box(&mut deque);
            deque.clear();
        });
    }

    #[bench]
    fn fill_back(bencher: &mut Bencher) {
        let mut buf: RingBuf<u8> = RingBuf::new();
        bencher.iter(|| {
            buf.fill_at_back(BLOCK_SIZE, 0);
            black_box(&mut buf);
            buf.clear();
        });
    }
}
