use std::collections::BTreeMap;
use std::ops::Range;

/// Set of ranges implemented with a BTreeMap. No overlapping ranges are
/// allowed. Consecutive ranges are merged.
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

    /// Test if a single value is contained in the set.
    pub fn has_value(&self, val: u64) -> bool {
        // ------ [ start ------------------ start + len ] ----
        //                              ^ val
        // search backwards
        let mut range_iter = self.map.range(..=val);
        if let Some((start, len)) = range_iter.next_back() {
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
        if let Some((start, len)) = range_iter.next_back() {
            start + len >= range.end
        } else {
            false
        }
    }

    /// Insert a range into the set
    pub fn insert_range(&mut self, new_range: Range<u64>) -> bool {
        // remove all existing intersecting ranges, extend new range if needed
        enum State {
            Initial { new_range: Range<u64> },
            RemoveExisting { new_range: Range<u64> },
            CheckCapacity { to_insert: Range<u64> },
            InsertNew { to_insert: Range<u64> },
        }

        let mut state = State::Initial { new_range };
        loop {
            // IMAGINE HAVING READABLE CODE
            state = match state {
                State::Initial { new_range } => {
                    // search backwards from end
                    let mut range_iter = self.map.range(..=new_range.end);
                    if let Some((start, len)) = range_iter.next_back() {
                        if *start <= new_range.start && start + len >= new_range.end {
                            // range already covered in set
                            return true;
                        } else if start + len < new_range.start {
                            // new range is after all existing ranges
                            State::CheckCapacity { to_insert: new_range }
                        } else {
                            // new range intersects an existing range
                            State::RemoveExisting { new_range }
                        }
                    } else {
                        // new range is before all existing ranges (or no ranges exist),
                        // insert new range after capacity check
                        State::CheckCapacity { to_insert: new_range }
                    }
                },
                State::RemoveExisting { mut new_range } => {
                    let range_iter = self.map.range(..=new_range.end);
                    let mut to_remove: Vec<u64> = Vec::new();
                    for (start, len) in range_iter.rev() {
                        if *start > new_range.start {
                            if start + len > new_range.end {
                                // intersecting or immediately following range extends
                                // past end of new range
                                new_range.end = start + len;
                            } else {
                                // intersecting range entirely contained with in new range
                            }
                            to_remove.push(*start);
                        } else {
                            if start + len < new_range.start {
                                // new range is entirely after current range (no intersection)
                                // no more ranges to search
                                break;
                            } else if start + len < new_range.end {
                                // intersecting range or immediately preceding range extends
                                // past start of new range
                                new_range.start = *start;
                                to_remove.push(*start);
                            } else {
                                // new range is entirely contained within existing range
                                // Initial should've handled this
                                unreachable!();
                            }
                        }
                    }
                    for s in to_remove {
                        self.map.remove(&s);
                    }

                    State::InsertNew { to_insert: new_range }
                },
                State::CheckCapacity { to_insert } => {
                    if self.map.len() >= self.max_size {
                        // set is full
                        return false;
                    }
                    State::InsertNew { to_insert }
                }
                State::InsertNew { to_insert } => {
                    self.map.insert(to_insert.start, to_insert.end - to_insert.start);
                    return true;
                }
            };
        }
    }

    /// Peek first value in set
    pub fn peek_first(&self) -> Option<Range<u64>> {
        self.map.first_key_value().map(|(start, len)| { *start..(start + len) })
    }

    /// Peek last value in set
    pub fn peek_last(&self) -> Option<Range<u64>> {
        self.map.last_key_value().map(|(start, len)| { *start..(start + len) })
    }

    /// Remove all ranges below a given value. Truncate ranges if they include the value.
    pub fn remove_until_from_first(&mut self, val: u64) {
        let mut to_remove: Vec<u64> = Vec::new();
        let mut adjust_start: Option<u64> = None;
        for (start, len) in self.map.range(..=val) {
            if start + len <= val {
                to_remove.push(*start);
            } else {
                adjust_start = Some(*start);
            }
        }
        for s in to_remove {
            self.map.remove(&s);
        }
        if let Some(adjust_start) = adjust_start {
            let len = self.map.remove(&adjust_start).unwrap();
            let end = adjust_start + len;
            self.map.insert(val, end - val);
        }
    }

    /// Dump all ranges in set
    pub fn dump_all(&self) {
        for (start, len) in self.map.iter() {
            println!("{}..{}", start, start + len);
        }
    }
}

#[cfg(test)]
mod test {
    use super::RangeSet;

    #[test]
    fn insert_distinct_range() {
        let mut rs = RangeSet::new(usize::MAX);
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
    }

    #[test]
    fn insert_overlapping_range() {
        let mut rs = RangeSet::new(usize::MAX);
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

        assert!(rs.has_value(0));
        assert!(rs.has_value(8));
        assert!(rs.has_value(60));

        assert!(!rs.has_value(20));
        assert!(!rs.has_value(75));

        assert!(rs.has_range(0..10));
        assert!(rs.has_range(0..15));
        assert!(rs.has_range(5..15));
        assert!(rs.has_range(10..15));
        assert!(rs.has_range(55..65));
        assert!(rs.has_range(85..95));
    }

    #[test]
    fn remove_until() {
        let mut rs = RangeSet::new(usize::MAX);
        assert!(rs.insert_range(0..10));
        assert!(rs.insert_range(20..30));
        assert!(rs.insert_range(40..50));
        assert!(rs.insert_range(60..70));
        assert!(rs.insert_range(80..90));

        rs.remove_until_from_first(15);
        assert_eq!(rs.peek_first(), Some(20..30));

        rs.remove_until_from_first(25);
        assert_eq!(rs.peek_first(), Some(25..30));
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
    }
}
