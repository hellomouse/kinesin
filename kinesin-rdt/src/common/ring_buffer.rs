use std::marker::PhantomData;
use std::mem::size_of;
use std::ops::{Bound, Range, RangeBounds};
use std::{ptr, slice};

/// ring buffer supporting batch copy in/out
///
/// safety: probably not
pub struct RingBuf<T> {
    // buf: [-----<(head)=====(head + len)>--]
    buf: Vec<T>,
    head: usize,
    len: usize,
}

/// an immutable element range of a RingBuf
pub struct RingBufSlice<'a, T> {
    buf: &'a RingBuf<T>,
    start: usize,
    end: usize,
}

/// a mutable element range of a RingBuf
pub struct RingBufSliceMut<'a, T> {
    buf: *mut RingBuf<T>,
    start: usize,
    end: usize,
    // disclaimer: i have very little clue as to what this actually does
    _marker: PhantomData<&'a RingBuf<T>>,
}

/// draining iterator implementation
pub struct Drain<'a, T> {
    /// associated RingBuf
    buf: &'a mut RingBuf<T>,
    /// index of next front element
    front: usize,
    /// index of next back element
    back: usize,
    /// remaining elements in iterator
    remaining: usize,
    /// head pointer before Drain creation
    prev_head: usize,
    // /// drain type
    // op_type: DrainType,
}

impl<T> RingBuf<T> {
    /// ensure T is not something strange
    const fn ensure_type_ok() {
        assert!(size_of::<T>() > 0, "cannot deal with zero-sized types");
    }

    /// create new buffer
    pub fn new() -> RingBuf<T> {
        Self::ensure_type_ok();
        RingBuf {
            buf: Vec::new(),
            head: 0,
            len: 0,
        }
    }

    /// create new buffer with preallocated capacity
    pub fn with_capacity(capacity: usize) -> RingBuf<T> {
        Self::ensure_type_ok();
        let mut vec = Vec::with_capacity(capacity);
        // safety: uninitialized bytes are not leaked
        unsafe { vec.set_len(vec.capacity()) };
        RingBuf {
            buf: vec,
            head: 0,
            len: 0,
        }
    }

    /// max capacity before reallocating
    pub fn capacity(&self) -> usize {
        self.buf.len()
    }

    /// length of buffer
    pub fn len(&self) -> usize {
        self.len
    }

    /// obtain pointer to backing buffer
    fn ptr(&self) -> *mut T {
        self.buf.as_ptr() as *mut _
    }

    /// obtain pointer to raw offset into backing buffer
    unsafe fn ptr_at(&self, offset: usize) -> *mut T {
        self.ptr().add(offset)
    }

    /// copy elements within backing buffer
    unsafe fn copy(&mut self, src: usize, dst: usize, count: usize) {
        ptr::copy(self.ptr_at(src), self.ptr_at(dst), count);
    }

    /// non-overlapping copy elements within backing buffer
    unsafe fn copy_nonoverlapping(&mut self, src: usize, dst: usize, count: usize) {
        ptr::copy_nonoverlapping(self.ptr_at(src), self.ptr_at(dst), count);
    }

    /// obtain slice to elements with raw index
    unsafe fn buf_slice_at(&self, range: Range<usize>) -> &[T] {
        slice::from_raw_parts(self.ptr_at(range.start), range.end - range.start)
    }

    /// obtain mutable slice to elements with raw index
    ///
    /// safety warning: will absolutely spit out aliasing mutable references if
    /// asked wrongly
    unsafe fn buf_slice_at_mut(&self, range: Range<usize>) -> &mut [T] {
        slice::from_raw_parts_mut(self.ptr_at(range.start), range.end - range.start)
    }

    /// determine if elements in backing buffer are in a contiguous segment
    pub fn is_contiguous(&self) -> bool {
        // did tail wrap?
        // head + len <= capacity
        self.head <= self.capacity() - self.len
    }

    /// get offset into backing buffer from element index
    #[inline]
    fn offset_of(&self, index: usize) -> usize {
        self.offset_of_explicit(self.head, index)
    }

    /// get offset into backing buffer from element index and explicit head index
    fn offset_of_explicit(&self, head: usize, index: usize) -> usize {
        // disclaimer: the math worked. outside of that, i have no idea what this does
        debug_assert!(index < self.capacity(), "index cannot exceed capacity");
        let remaining = self.capacity() - index;
        if head < remaining {
            // does not wrap
            head + index
        } else {
            // does wrap
            head - remaining
        }
    }

    /// get offset into backing buffer of backwards element index
    fn offset_of_reverse(&self, negative_index: usize) -> usize {
        // disclaimer: same as above
        debug_assert!(
            negative_index < self.capacity(),
            "index cannot exceed capacity"
        );
        if self.head >= negative_index {
            // does not wrap
            self.head - negative_index
        } else {
            // does wrap
            self.head + (self.capacity() - negative_index)
        }
    }

    /// handle resize of backing buffer to a larger capacity
    unsafe fn handle_buf_expand(&mut self, old_capacity: usize) {
        let new_capacity = self.capacity();

        if self.head <= old_capacity - self.len {
            // was contiguous, do nothing
        } else {
            let head_segment_len = old_capacity - self.head;
            let tail_segment_len = self.len - head_segment_len;

            if head_segment_len > tail_segment_len
                && new_capacity - old_capacity >= tail_segment_len
            {
                // we can fit the tail segment after the head segment
                // from: [==>------<======-----]
                // to:   [---------<========>--]
                self.copy_nonoverlapping(0, old_capacity, tail_segment_len);
            } else {
                // copy head segment to the end
                // from: [========>----<====---]
                // to:   [========>-------<====]
                let new_head = new_capacity - head_segment_len;
                self.copy(self.head, new_head, head_segment_len);
                self.head = new_head;
            }
        }
    }

    /// realign all elements so they are contiguous at the beginning of the buffer
    pub fn realign(&mut self) {
        if self.head == 0 {
            // already aligned, nothing to do
            return;
        }

        unsafe {
            if self.is_contiguous() {
                // copy to start
                self.copy(self.head, 0, self.len);
            } else {
                // copy head end to start
                // from: [===>-----<=====]
                // to:   [===><=====-----]
                let head_segment_len = self.capacity() - self.head;
                let tail_segment_len = self.len - head_segment_len;
                self.copy(self.head, tail_segment_len, head_segment_len);

                // rotate segment
                // from: [===><=====-----]
                // to:   [<========>-----]
                let slice = self.buf_slice_at_mut(0..self.len);
                slice.rotate_left(tail_segment_len);
            }

            self.head = 0;
        }
    }

    /// reserve space for at least `count` more elements
    pub fn reserve(&mut self, count: usize) {
        let desired_capacity = self.len.checked_add(count).expect("capacity overflow");
        if desired_capacity > self.capacity() {
            let old_capacity = self.capacity();
            self.buf.reserve(desired_capacity - old_capacity);
            unsafe {
                self.buf.set_len(self.buf.capacity());
                self.handle_buf_expand(old_capacity);
            }
        }
    }

    /// reserve space for exactly `count` more elements (see Vec::reserve_exact)
    pub fn reserve_exact(&mut self, count: usize) {
        let desired_capacity = self.len.checked_add(count).expect("capacity overflow");
        if desired_capacity > self.capacity() {
            let old_capacity = self.capacity();
            self.buf.reserve_exact(desired_capacity - old_capacity);
            unsafe {
                self.buf.set_len(self.buf.capacity());
                self.handle_buf_expand(old_capacity);
            }
        }
    }

    /// shrink backing buffer to given capacity
    pub fn shrink_to(&mut self, target_capacity: usize) {
        assert!(
            target_capacity <= self.capacity(),
            "cannot shrink to a greater capacity (old: {}, requested: {})",
            self.capacity(),
            target_capacity
        );

        // ensure elements are aligned to start
        self.realign();
        let requested_capacity = usize::max(target_capacity, self.len);
        let old_capacity = self.capacity();

        unsafe {
            // request shrink to size
            self.buf.set_len(requested_capacity);
            self.buf.shrink_to(requested_capacity);
            // ensure correct size
            let new_capacity = self.buf.capacity();
            self.buf.set_len(new_capacity);
            debug_assert!(
                new_capacity <= old_capacity,
                "Vec::shrink_to did not shrink?"
            );
        }
    }

    /// push one element to back of ring
    pub fn push_back(&mut self, val: T) {
        self.reserve(1);
        unsafe {
            // append to tail side
            let target = self.ptr_at(self.offset_of(self.len));
            ptr::write(target, val);
        }
        self.len += 1;
    }

    /// push one element to front of ring
    pub fn push_front(&mut self, val: T) {
        self.reserve(1);
        // append to head side
        let new_head = self.offset_of_reverse(1);
        unsafe {
            let target = self.ptr_at(new_head);
            ptr::write(target, val);
        }
        self.head = new_head;
        self.len += 1;
    }

    /// pop one element from back of ring
    pub fn pop_back(&mut self) -> Option<T> {
        if self.len == 0 {
            return None;
        }

        let out;
        unsafe {
            let target = self.ptr_at(self.offset_of(self.len));
            out = ptr::read(target);
            self.len -= 1;
        }

        Some(out)
    }

    /// pop one element from front of ring
    pub fn pop_front(&mut self) -> Option<T> {
        if self.len == 0 {
            return None;
        }

        let out;
        unsafe {
            let target = self.ptr_at(self.offset_of(0));
            out = ptr::read(target);
            self.head = self.offset_of(1);
            self.len -= 1;
        }

        Some(out)
    }

    /// ensure provided index range is sane
    fn check_range(&self, range: &Range<usize>) {
        assert!(range.start <= range.end, "range cannot be reverse");
        assert!(range.start < self.len, "range start out of bounds");
        assert!(range.end <= self.len, "range end out of bounds");
    }

    /// map element index range to backing buffer range(s)
    #[inline]
    fn map_range(&self, range: Range<usize>) -> (Range<usize>, Option<Range<usize>>) {
        self.map_range_explicit(self.head, range)
    }

    /// map element index range to backing buffer range(s) with explicit head index
    fn map_range_explicit(
        &self,
        head: usize,
        range: Range<usize>,
    ) -> (Range<usize>, Option<Range<usize>>) {
        if range.start == range.end {
            // zero size range
            return (head..head, None);
        }
        let start = self.offset_of_explicit(head, range.start);
        let end = self.offset_of_explicit(head, range.end - 1);

        if end >= start {
            // range does not wrap
            (start..end + 1, None)
        } else {
            // range does wrap
            (start..self.capacity(), Some(0..end + 1))
        }
    }

    /// get immutable reference to range
    pub fn range<'a>(&'a self, range: Range<usize>) -> RingBufSlice<'a, T> {
        self.check_range(&range);
        RingBufSlice {
            buf: self,
            start: range.start,
            end: range.end,
        }
    }

    /// get mutable reference to range
    pub fn range_mut<'a>(&'a mut self, range: Range<usize>) -> RingBufSliceMut<'a, T> {
        self.check_range(&range);
        RingBufSliceMut {
            buf: self,
            start: range.start,
            end: range.end,
            _marker: PhantomData,
        }
    }

    /// get slice(s) corresponding to range
    unsafe fn range_to_slices<'a>(&'a self, range: Range<usize>) -> (&'a [T], Option<&'a [T]>) {
        let (a, b) = self.map_range(range);
        (self.buf_slice_at(a), b.map(|r| self.buf_slice_at(r)))
    }

    /// get mutable slice(s) corresponding to range
    ///
    /// safety warning: must ensure slices do not alias
    unsafe fn range_to_slices_mut<'a>(
        &'a self,
        range: Range<usize>,
    ) -> (&'a mut [T], Option<&'a mut [T]>) {
        let (a, b) = self.map_range(range);
        (
            self.buf_slice_at_mut(a),
            b.map(|r| self.buf_slice_at_mut(r)),
        )
    }

    /// clear all elements
    pub fn clear(&mut self) {
        unsafe {
            // get active ranges
            let (a, b) = self.map_range(0..self.len);
            self.head = 0;
            self.len = 0;

            let slice_a: *mut [T] = self.buf_slice_at_mut(a);
            ptr::drop_in_place(slice_a);
            if let Some(b) = b {
                let slice_b: *mut [T] = self.buf_slice_at_mut(b);
                ptr::drop_in_place(slice_b);
            }
        }
    }

    /// remove range of elements from RingBuf and return iterator for those elements
    ///
    /// Currently only supports draining from either the start or the end.
    /// Drained elements are dropped when the iterator is dropped.
    pub fn drain<'a, R: RangeBounds<usize>>(&'a mut self, range: R) -> Drain<'a, T> {
        let lower_bound = match range.start_bound() {
            Bound::Included(&start) => {
                assert!(start < self.len, "start index out of bounds");
                Some(start)
            }
            Bound::Excluded(&start) => {
                let start = start.checked_add(1).expect("start index out of bounds");
                assert!(start < self.len, "start index out of bounds");
                Some(start)
            }
            Bound::Unbounded => None,
        };
        let upper_bound = match range.end_bound() {
            Bound::Included(&end) => {
                let end = end.checked_add(1).expect("range out of bounds");
                assert!(end <= self.len, "end index out of bounds");
                Some(end)
            }
            Bound::Excluded(&end) => {
                assert!(end <= self.len, "end index out of bounds");
                Some(end)
            }
            Bound::Unbounded => None,
        };

        if let Some(start) = lower_bound {
            if let Some(_end) = upper_bound {
                unimplemented!("drain from middle unimplemented");
            } else {
                // drain until end
                Drain::to_end(self, start)
            }
        } else {
            if let Some(end) = upper_bound {
                // drain from start
                Drain::from_start(self, end)
            } else {
                // drain everything
                Drain::from_start(self, self.len)
            }
        }
    }
}

// this was a bad idea
impl<T: Copy> RingBuf<T> {
    /// copy elements from slice into buffer ranges
    unsafe fn copy_range_from_slice(
        &mut self,
        range_a: Range<usize>,
        range_b: Option<Range<usize>>,
        elements: &[T],
    ) {
        if let Some(b) = range_b {
            // split copy
            debug_assert_eq!(
                b.end - b.start + range_a.end - range_a.start,
                elements.len(),
                "range incorrect"
            );
            unsafe {
                // copy first range
                let dest_a = self.ptr_at(range_a.start);
                let length_a = range_a.end - range_a.start;
                ptr::copy_nonoverlapping(elements.as_ptr(), dest_a, length_a);
                // copy second range
                let dest_b = self.ptr_at(b.start);
                let length_b = elements.len() - length_a;
                ptr::copy_nonoverlapping(elements.as_ptr().add(length_a), dest_b, length_b);
            }
        } else {
            // oneshot copy
            debug_assert_eq!(
                range_a.end - range_a.start,
                elements.len(),
                "range incorrect"
            );
            unsafe {
                let dest = self.ptr_at(range_a.start);
                ptr::copy_nonoverlapping(elements.as_ptr(), dest, range_a.end - range_a.start);
            }
        }
    }

    /// copy elements from buffer ranges to slice
    unsafe fn copy_range_to_slice(
        &self,
        range_a: Range<usize>,
        range_b: Option<Range<usize>>,
        to_slice: &mut [T],
    ) {
        if let Some(b) = range_b {
            // split copy
            debug_assert_eq!(
                b.end - b.start + range_a.end - range_a.start,
                to_slice.len(),
                "range incorrect"
            );
            unsafe {
                // copy first range
                let source_a = self.ptr_at(range_a.start) as *const T;
                let length_a = range_a.end - range_a.start;
                ptr::copy_nonoverlapping(source_a, to_slice.as_mut_ptr(), length_a);
                // copy second range
                let source_b = self.ptr_at(b.start) as *const T;
                let length_b = to_slice.len() - length_a;
                ptr::copy_nonoverlapping(source_b, to_slice.as_mut_ptr().add(length_a), length_b);
            }
        } else {
            // oneshot copy
            debug_assert_eq!(
                range_a.end - range_a.start,
                to_slice.len(),
                "range incorrect"
            );
            unsafe {
                let source = self.ptr_at(range_a.start) as *const T;
                ptr::copy_nonoverlapping(
                    source,
                    to_slice.as_mut_ptr(),
                    range_a.end - range_a.start,
                );
            }
        }
    }

    /// push contents of slice to back by copying
    pub fn push_back_copy_from_slice(&mut self, elements: &[T]) {
        self.reserve(elements.len());
        let (a, b) = self.map_range(self.len..self.len + elements.len());
        unsafe { self.copy_range_from_slice(a, b, elements) };
        self.len += elements.len();
    }

    /// push contents of slice to front by copying
    pub fn push_front_copy_from_slice(&mut self, elements: &[T]) {
        self.reserve(elements.len());
        let new_head = self.offset_of_reverse(elements.len());
        let (a, b) = self.map_range_explicit(new_head, 0..elements.len());
        unsafe { self.copy_range_from_slice(a, b, elements) };
        self.head = new_head;
        self.len += elements.len();
    }

    pub fn get(&self, index: usize) -> Option<&T> {
        if index < self.len {
            unsafe { Some(&*self.ptr_at(self.offset_of(index))) }
        } else {
            None
        }
    }

    pub fn get_mut(&mut self, index: usize) -> Option<&mut T> {
        if index < self.len {
            unsafe { Some(&mut *self.ptr_at(self.offset_of(index))) }
        } else {
            None
        }
    }

    /// pop contents to slice from back by copying
    pub fn pop_back_copy_to_slice(&mut self, dest: &mut [T]) {
        assert!(dest.len() <= self.len, "destination slice too large");
        let new_len = self.len - dest.len();
        let (a, b) = self.map_range(new_len..self.len);
        self.len = new_len;
        unsafe { self.copy_range_to_slice(a, b, dest) };
    }

    /// pop contents to slice from front by copying
    pub fn pop_front_copy_to_slice(&mut self, dest: &mut [T]) {
        assert!(dest.len() <= self.len, "destination slice too large");
        let (a, b) = self.map_range(0..dest.len());
        self.head = self.offset_of(dest.len());
        self.len -= dest.len();
        unsafe { self.copy_range_to_slice(a, b, dest) };
    }
}

fn validate_subrange(r1: Range<usize>, r2: &Range<usize>) -> Range<usize> {
    assert!(r2.start <= r2.end, "range cannot be reverse");
    let new_start = r1.start.checked_add(r2.start).expect("start out of range");
    let new_end = r1.start.checked_add(r2.end).expect("end out of range");
    assert!(new_start < r1.end, "start out of range");
    assert!(new_end <= r1.end, "end out of range");
    new_start..new_end
}

impl<'a, T> RingBufSlice<'a, T> {
    /// get length of slice
    pub fn len(&self) -> usize {
        self.end - self.start
    }

    /// get slices representing range
    pub fn as_slices(&self) -> (&'a [T], Option<&'a [T]>) {
        unsafe { self.buf.range_to_slices(self.start..self.end) }
    }

    /// get sub-range into range
    pub fn range(&self, range: Range<usize>) -> RingBufSlice<'a, T> {
        let new_range = validate_subrange(self.start..self.end, &range);
        RingBufSlice {
            buf: self.buf,
            start: new_range.start,
            end: new_range.end,
        }
    }
}

impl<'a, T: Copy> RingBufSlice<'a, T> {
    /// copy contents of range to a slice
    pub fn copy_to_slice(&self, slice: &mut [T]) {
        assert_eq!(self.len(), slice.len(), "length mismatch");
        unsafe {
            let (a, b) = self.buf.map_range(self.start..self.end);
            self.buf.copy_range_to_slice(a, b, slice);
        }
    }
}

impl<'a, T> RingBufSliceMut<'a, T> {
    /// get length of slice
    pub fn len(&self) -> usize {
        self.end - self.start
    }

    /// get slices representing range
    pub fn as_slices(&self) -> (&'a [T], Option<&'a [T]>) {
        unsafe { (*self.buf).range_to_slices(self.start..self.end) }
    }

    /// get mutable slices representing range
    pub fn as_mut_slices(&mut self) -> (&'a mut [T], Option<&'a mut [T]>) {
        unsafe { (*self.buf).range_to_slices_mut(self.start..self.end) }
    }

    /// get sub-range into range
    pub fn range(&self, range: Range<usize>) -> RingBufSlice<'a, T> {
        let new_range = validate_subrange(self.start..self.end, &range);
        unsafe {
            // safety: write operations cannot be performed on RingBufSlice
            RingBufSlice {
                buf: &*self.buf,
                start: new_range.start,
                end: new_range.end,
            }
        }
    }

    /// get mutable sub-range into range
    pub fn range_mut(&mut self, range: Range<usize>) -> RingBufSliceMut<'a, T> {
        let new_range = validate_subrange(self.start..self.end, &range);
        RingBufSliceMut {
            buf: self.buf,
            start: new_range.start,
            end: new_range.end,
            _marker: PhantomData,
        }
    }

    /// split into two mutable slices at index
    pub fn split_at_mut(self, index: usize) -> (RingBufSliceMut<'a, T>, RingBufSliceMut<'a, T>) {
        let split_index = index.checked_add(self.start).expect("index out of range");
        assert!(split_index < self.end, "split index out of range");

        (
            RingBufSliceMut {
                buf: self.buf,
                start: self.start,
                end: split_index,
                _marker: PhantomData,
            },
            RingBufSliceMut {
                buf: self.buf,
                start: split_index,
                end: self.end,
                _marker: PhantomData,
            },
        )
    }
}

impl<'a, T: Copy> RingBufSliceMut<'a, T> {
    /// copy contents of range to a slice
    pub fn copy_to_slice(&self, slice: &mut [T]) {
        assert_eq!(self.len(), slice.len(), "length mismatch");
        unsafe {
            let (a, b) = (*self.buf).map_range(self.start..self.end);
            (*self.buf).copy_range_to_slice(a, b, slice);
        }
    }

    /// copy contents of a slice to the range
    pub fn copy_from_slice(&self, slice: &[T]) {
        assert_eq!(self.len(), slice.len(), "length mismatch");
        unsafe {
            let (a, b) = (*self.buf).map_range(self.start..self.end);
            (*self.buf).copy_range_from_slice(a, b, slice);
        }
    }
}

impl<T> Drop for RingBuf<T> {
    fn drop(&mut self) {
        unsafe {
            // ensure Vec does not drop garbage
            self.realign();
            self.buf.set_len(self.len);
        }
    }
}

impl<'a, T> Drain<'a, T> {
    /// create a Drain for the range [0, until)
    fn from_start(buf: &'a mut RingBuf<T>, until: usize) -> Drain<'a, T> {
        let prev_head = buf.head;
        let drain = Drain {
            buf,
            front: 0,
            back: until,
            remaining: until,
            prev_head,
        };
        drain.buf.head = until;
        drain.buf.len -= until;
        drain
    }

    /// create a Drain for the range [starting_from, buf.len)
    fn to_end(buf: &'a mut RingBuf<T>, starting_from: usize) -> Drain<'a, T> {
        let prev_head = buf.head;
        let back = buf.len;
        let remaining = buf.len - starting_from;
        let drain = Drain {
            buf,
            front: starting_from,
            back,
            remaining,
            prev_head,
        };
        drain.buf.len -= starting_from;
        drain
    }
}

impl<'a, T> Drop for Drain<'a, T> {
    fn drop(&mut self) {
        if self.remaining == 0 {
            // nothing to drop
            return;
        }

        unsafe {
            // drop everything remaining in iterator
            let (a, b) = self
                .buf
                .map_range_explicit(self.prev_head, self.front..self.back);
            let slice_a: *mut [T] = self.buf.buf_slice_at_mut(a);
            ptr::drop_in_place(slice_a);
            if let Some(b) = b {
                let slice_b: *mut [T] = self.buf.buf_slice_at_mut(b);
                ptr::drop_in_place(slice_b);
            }
        }
    }
}

impl<'a, T> Iterator for Drain<'a, T> {
    type Item = T;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            None
        } else {
            unsafe {
                let element = self
                    .buf
                    .ptr_at(self.buf.offset_of_explicit(self.prev_head, self.front));
                self.front += 1;
                self.remaining -= 1;
                Some(ptr::read(element))
            }
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.remaining, Some(self.remaining))
    }
}

impl<'a, T> DoubleEndedIterator for Drain<'a, T> {
    fn next_back(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            None
        } else {
            unsafe {
                self.back -= 1;
                self.remaining -= 1;
                let element = self
                    .buf
                    .ptr_at(self.buf.offset_of_explicit(self.prev_head, self.back));
                Some(ptr::read(element))
            }
        }
    }
}

impl<'a, T> ExactSizeIterator for Drain<'a, T> {}

#[cfg(test)]
mod test {
    // DISCLAIMER: this "test suite" is in absolutely no way exhaustive and
    // should not in any way, shape, or form serve as reassurance that the
    // RingBuf implementation above is safe for anything at all

    use super::*;

    #[test]
    fn new() {
        let mut buf: RingBuf<String> = RingBuf::new();
        buf.push_back("world".into());
        buf.push_back("!".into());
        buf.push_front(", ".into());
        buf.push_front("Hello".into());

        assert_eq!(buf.pop_front(), Some("Hello".into()));
        assert_eq!(buf.pop_front(), Some(", ".into()));
        assert_eq!(buf.pop_front(), Some("world".into()));
        assert_eq!(buf.pop_front(), Some("!".into()));
        assert_eq!(buf.pop_front(), None);
    }

    #[test]
    fn copy_around_slices() {
        let mut buf: RingBuf<u8> = RingBuf::new();
        buf.push_back_copy_from_slice(&[5, 6, 7, 8, 9, 10, 11]);
        buf.push_front_copy_from_slice(&[0, 1, 2, 3, 4]);
        assert_eq!(buf.get(3), Some(&3));
        assert_eq!(buf.get(7), Some(&7));
        
        let sliced = buf.range(3..6);
        let mut dest = [0u8; 3];
        sliced.copy_to_slice(&mut dest);
        assert_eq!(dest, [3, 4, 5]);
        
        let mut dest = [0u8; 6];
        buf.pop_front_copy_to_slice(&mut dest);
        assert_eq!(dest, [0, 1, 2, 3, 4, 5]);
        buf.pop_back_copy_to_slice(&mut dest);
        assert_eq!(dest, [6, 7, 8, 9, 10, 11]);
    }

    #[test]
    fn copy_from_slice() {
        let mut buf: RingBuf<u8> = RingBuf::new();
        buf.push_back_copy_from_slice(&[0u8; 4096]);

        let slice_mut = buf.range_mut(1024..2048);
        slice_mut.copy_from_slice(&[1u8; 1024]);

        buf.drain(..1024);

        assert_eq!(buf.get(1024), Some(&0));
        assert_eq!(buf.get(512), Some(&1));

        buf.push_front_copy_from_slice(&[2u8; 1024]);

        assert_eq!(buf.get(512), Some(&2));
        assert_eq!(buf.get(1536), Some(&1));
        assert_eq!(buf.get(3072), Some(&0));
    }

    #[test]
    fn drain() {
        let mut buf: RingBuf<String> = RingBuf::new();
        buf.push_back("Hello, ".into());
        buf.push_back("world!".into());
        
        for i in 0..10 {
            buf.push_back(i.to_string());
        }

        let a: Vec<String> = buf.drain(..2).collect();
        assert_eq!(a.join(""), "Hello, world!");
        let b: Vec<String> = buf.drain(..).collect();
        assert_eq!(b.join(""), "0123456789");
        assert_eq!(buf.len(), 0);
    }
}
