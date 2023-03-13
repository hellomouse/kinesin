use std::collections::BTreeMap;
use std::ops::{Bound, Range, RangeBounds};

// TODO: this is apparently massively horrible
/// Set of ranges implemented with a BTreeMap. No overlapping ranges are
/// allowed. Consecutive ranges are merged. Representable ranges are
/// [0, u64::MAX).
pub struct RangeSet {
    /// Backing map, where key = start and value = length.
    map: BTreeMap<u64, u64>,
    max_size: usize,
}

impl RangeSet {
    pub fn new(max_size: usize) -> RangeSet {
        RangeSet {
            map: BTreeMap::new(),
            max_size,
        }
    }

    pub fn unlimited() -> RangeSet {
        Self::new(usize::MAX)
    }

    /// Test if a single value is contained in the set.
    pub fn has_value(&self, val: u64) -> bool {
        // ------ [ start ------------------ start + len ] ----
        //                              ^ val
        // search backwards
        let mut range_iter = self.map.range(..=val);
        if let Some((&start, &len)) = range_iter.next_back() {
            start + len > val
        } else {
            false
        }
    }

    /// Test if a range is contained in the set
    pub fn has_range(&self, range: Range<u64>) -> bool {
        // ------ [ start ------------------ start + len ] ----
        // ------------ [ range ---------------------- ] ------
        let mut range_iter = self.map.range(..=range.start);
        if let Some((&start, &len)) = range_iter.next_back() {
            start + len >= range.end
        } else {
            false
        }
    }

    fn _direct_insert(&mut self, new_range: Range<u64>) {
        self.map
            .insert(new_range.start, new_range.end - new_range.start);
    }

    fn _max_checked_insert(&mut self, new_range: Range<u64>) -> bool {
        if self.map.len() >= self.max_size {
            // set is full
            false
        } else {
            self._direct_insert(new_range);
            true
        }
    }

    fn _intersecting_insert(&mut self, mut new_range: Range<u64>) {
        let range_iter = self.map.range(..=new_range.end);
        let mut to_remove: Vec<u64> = Vec::new();
        for (&start, &len) in range_iter.rev() {
            let end = start + len;
            if start > new_range.start {
                if end > new_range.end {
                    // intersecting or immediately following range extends
                    // past end of new range
                    new_range.end = end;
                } else {
                    // intersecting range entirely contained with in new range
                }
                to_remove.push(start);
            } else if end < new_range.start {
                // new range is entirely after current range (no intersection)
                // no more ranges to search
                break;
            } else if end < new_range.end {
                // intersecting range or immediately preceding range extends
                // past start of new range
                new_range.start = start;
                to_remove.push(start);
            } else {
                // new range is entirely contained within existing range
                // Initial should've handled this
                unreachable!();
            }
        }
        for s in to_remove {
            self.map.remove(&s);
        }

        self._direct_insert(new_range);
    }

    /// Insert a range into the set
    pub fn insert_range(&mut self, new_range: Range<u64>) -> bool {
        if new_range.start == new_range.end {
            panic!("cannot insert zero-length range");
        }
        let mut range_iter = self.map.range(..=new_range.end);
        if let Some((&start, &len)) = range_iter.next_back() {
            let end = start + len;
            if start <= new_range.start && end >= new_range.end {
                // range already covered in set
                true
            } else if end < new_range.start {
                // new range is after all existing ranges
                self._max_checked_insert(new_range)
            } else {
                // new range intersects or is adjacent to an existing range
                self._intersecting_insert(new_range);
                true
            }
        } else {
            // new range is before all existing ranges (or no ranges exist),
            // insert new range after capacity check
            self._max_checked_insert(new_range)
        }
    }

    /// Remove range from set
    pub fn remove_range<R: RangeBounds<u64>>(&mut self, to_remove: R) -> usize {
        let lower_bound = match to_remove.start_bound() {
            Bound::Included(start) => *start,
            Bound::Excluded(start) => start.checked_add(1).expect("range out of bounds"),
            Bound::Unbounded => 0,
        };
        let upper_bound = match to_remove.end_bound() {
            Bound::Included(end) => end.checked_add(1).expect("range out of bounds"),
            Bound::Excluded(end) => *end,
            Bound::Unbounded => u64::MAX,
        };

        if lower_bound == upper_bound {
            panic!("cannot remove zero-length range");
        }

        let mut affected = 0;
        let range_iter = self.map.range((Bound::Unbounded, to_remove.end_bound()));
        let mut pending_ops: Vec<(u64, Option<u64>)> = Vec::new();

        for (&start, &len) in range_iter.rev() {
            let end = start + len;
            if end <= lower_bound {
                // no more ranges could possibly match
                break;
            } else if end <= upper_bound {
                if start >= lower_bound {
                    // range is entirely contained within to_remove
                    pending_ops.push((start, None));
                    affected += 1;
                } else {
                    // range extends into to_remove
                    pending_ops.push((start, Some(lower_bound - start)));
                    affected += 1;
                    break;
                }
            } else if end > upper_bound {
                if start < lower_bound {
                    // current range includes to_remove, split range
                    pending_ops.push((start, Some(lower_bound - start)));
                    pending_ops.push((upper_bound, Some(end - upper_bound)));
                    affected += 1;
                    break;
                } else {
                    // current range starts within and extends past end of to_remove,
                    // trim start of range
                    // delete old range
                    pending_ops.push((start, None));
                    // insert trimmed range
                    pending_ops.push((upper_bound, Some(end - upper_bound)));
                    affected += 1;
                }
            } else {
                unreachable!();
            }
        }
        for (start, maybe_len) in pending_ops {
            if let Some(len) = maybe_len {
                self.map.insert(start, len);
            } else {
                self.map.remove(&start);
            }
        }
        affected
    }

    /// Peek first value in set
    pub fn peek_first(&self) -> Option<Range<u64>> {
        self.map
            .first_key_value()
            .map(|(&start, &len)| start..(start + len))
    }

    /// Peek last value in set
    pub fn peek_last(&self) -> Option<Range<u64>> {
        self.map
            .last_key_value()
            .map(|(&start, &len)| start..(start + len))
    }

    /// Dump all ranges in set
    pub fn dump_all(&self) {
        for (&start, &len) in self.map.iter() {
            println!("{}..{}", start, start + len);
        }
    }
}

#[cfg(test)]
mod test {
    use super::RangeSet;

    fn ensure_consistency(rs: &RangeSet) {
        assert!(rs.map.len() > 0);
        let mut iter = rs.map.iter();
        let first_el = iter.next().unwrap();
        let mut last_end = first_el.0 + first_el.1;

        for (&start, &len) in iter {
            assert!(start > last_end);
            assert!(len > 0);
            let did_overflow;
            (last_end, did_overflow) = start.overflowing_add(len);
            assert!(!did_overflow);
        }
    }

    #[test]
    fn insert_distinct_range() {
        let mut rs = RangeSet::unlimited();
        assert!(rs.insert_range(0..10));
        assert!(rs.insert_range(20..30));
        assert!(rs.insert_range(40..50));
        assert!(rs.insert_range(60..70));
        assert!(rs.insert_range(80..90));

        assert!(rs.has_value(0));
        assert!(rs.has_value(1));
        assert!(!rs.has_value(10));
        assert!(!rs.has_value(15));

        assert!(rs.has_range(0..10));
        assert!(rs.has_range(3..8));
        assert!(!rs.has_range(0..30));
        assert!(!rs.has_range(12..18));

        assert_eq!(rs.peek_first(), Some(0..10));

        ensure_consistency(&rs);
    }

    #[test]
    fn insert_overlapping_range() {
        let mut rs = RangeSet::unlimited();
        // overlapping ranges
        assert!(rs.insert_range(0..10));
        assert!(rs.insert_range(5..15));
        assert_eq!(rs.peek_last(), Some(0..15));
        assert!(rs.insert_range(30..40));
        assert!(rs.insert_range(25..35));
        assert_eq!(rs.peek_last(), Some(25..40));
        // adjacent ranges should be merged
        assert!(rs.insert_range(50..60));
        assert!(rs.insert_range(60..70));
        assert_eq!(rs.peek_last(), Some(50..70));
        assert!(rs.insert_range(90..100));
        assert!(rs.insert_range(80..90));
        assert_eq!(rs.peek_last(), Some(80..100));
        assert!(!rs.has_value(75));
        assert!(rs.insert_range(70..80));
        assert_eq!(rs.peek_last(), Some(50..100));
        assert!(rs.insert_range(100..101));
        assert_eq!(rs.peek_last(), Some(50..101));

        assert!(rs.has_value(0));
        assert!(rs.has_value(8));
        assert!(rs.has_value(60));

        assert!(!rs.has_value(20));

        assert!(rs.has_range(0..10));
        assert!(rs.has_range(0..15));
        assert!(rs.has_range(5..15));
        assert!(rs.has_range(10..15));
        assert!(rs.has_range(55..65));
        assert!(rs.has_range(85..95));

        ensure_consistency(&rs);
    }

    #[test]
    fn remove_until() {
        let mut rs = RangeSet::unlimited();
        assert!(rs.insert_range(0..10));
        assert!(rs.insert_range(20..30));
        assert!(rs.insert_range(40..50));
        assert!(rs.insert_range(60..70));
        assert!(rs.insert_range(80..90));

        rs.remove_range(..15);
        assert_eq!(rs.peek_first(), Some(20..30));

        rs.remove_range(..25);
        assert_eq!(rs.peek_first(), Some(25..30));

        ensure_consistency(&rs);
    }

    #[test]
    fn limits() {
        let mut rs = RangeSet::new(5);
        assert!(rs.insert_range(0..10));
        assert!(rs.insert_range(20..30));
        assert!(rs.insert_range(40..50));
        assert!(rs.insert_range(60..70));
        assert!(rs.insert_range(80..90));
        assert_eq!(rs.map.len(), 5);

        assert!(!rs.insert_range(100..110));
        assert_eq!(rs.map.len(), 5);

        assert!(rs.insert_range(10..15));
        assert_eq!(rs.map.len(), 5);
        assert_eq!(rs.peek_first(), Some(0..15));

        assert!(rs.insert_range(69..81));
        assert_eq!(rs.peek_last(), Some(60..90));
        assert_eq!(rs.map.len(), 4);

        ensure_consistency(&rs);
    }

    #[test]
    fn remove_range() {
        let mut rs = RangeSet::unlimited();
        assert!(rs.insert_range(0..10));
        assert!(rs.insert_range(20..30));
        assert!(rs.insert_range(40..50));

        assert_eq!(rs.remove_range(5..45), 3);
        assert_eq!(rs.map.len(), 2);
        assert_eq!(rs.peek_first(), Some(0..5));
        assert_eq!(rs.peek_last(), Some(45..50));

        rs.remove_range(..100);
        assert_eq!(rs.map.len(), 0);

        assert!(rs.insert_range(0..100));
        assert_eq!(rs.remove_range(25..75), 1);
        assert_eq!(rs.map.len(), 2);
        assert_eq!(rs.peek_first(), Some(0..25));
        assert_eq!(rs.peek_last(), Some(75..100));

        assert_eq!(rs.remove_range(75..100), 1);
        assert_eq!(rs.map.len(), 1);
        assert_eq!(rs.peek_first(), Some(0..25));

        assert!(rs.insert_range(50..75));
        assert!(rs.insert_range(80..100));
        assert!(rs.insert_range(120..150));
        assert_eq!(rs.remove_range(60..90), 2);

        assert_eq!(rs.map.len(), 4);
        assert_eq!(rs.peek_first(), Some(0..25));
        assert_eq!(rs.peek_last(), Some(120..150));
        assert!(rs.has_range(50..60));
        assert!(rs.has_range(90..100));
        assert!(!rs.has_value(60));
        assert!(!rs.has_value(70));
        assert!(rs.has_value(90));

        ensure_consistency(&rs);
    }
}
