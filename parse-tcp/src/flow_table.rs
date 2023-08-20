use std::net::IpAddr;

#[derive(Debug, Clone)]
pub struct FlowId {
    pub src_addr: IpAddr,
    pub src_port: u16,
    pub dst_addr: IpAddr,
    pub dst_port: u16,
}

impl PartialEq for FlowId {
    fn eq(&self, other: &Self) -> bool {
        if self.src_addr == other.src_addr
            && self.dst_addr == other.dst_addr
            && self.src_port == other.src_port
            && self.dst_port == other.dst_port
        {
            // exact match
            true
        } else if self.src_addr == other.dst_addr
            && self.dst_addr == other.src_addr
            && self.src_port == other.dst_port
            && self.dst_port == other.src_port
        {
            // reverse direction
            true
        } else {
            false
        }
    }
}

impl Eq for FlowId {}

impl std::hash::Hash for FlowId {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        // order independent hashing
        if self.src_addr <= self.dst_addr {
            self.src_addr.hash(state);
            self.dst_addr.hash(state);
        } else {
            self.dst_addr.hash(state);
            self.src_addr.hash(state);
        }
        if self.src_port <= self.dst_port {
            self.src_port.hash(state);
            self.dst_port.hash(state);
        } else {
            self.dst_port.hash(state);
            self.src_port.hash(state);
        }
    }
}

#[cfg(test)]
mod test {
    use std::collections::HashMap;
    use std::net::Ipv4Addr;

    use super::FlowId;

    #[test]
    fn hash_map() {
        let forward = FlowId {
            src_addr: Ipv4Addr::new(10, 3, 160, 24).into(),
            src_port: 35619,
            dst_addr: Ipv4Addr::new(1, 1, 1, 1).into(),
            dst_port: 53,
        };
        let reverse = FlowId {
            src_addr: forward.dst_addr.clone(),
            src_port: forward.dst_port,
            dst_addr: forward.src_addr.clone(),
            dst_port: forward.src_port,
        };
        let unrelated = FlowId {
            src_addr: Ipv4Addr::new(10, 3, 160, 24).into(),
            src_port: 35619,
            dst_addr: Ipv4Addr::new(8, 8, 8, 8).into(),
            dst_port: 53,
        };
        assert_eq!(forward, reverse);
        assert_ne!(forward, unrelated);
        
        let mut map: HashMap<FlowId, String> = HashMap::new();
        map.insert(forward.clone(), "test 1".into());
        assert_eq!(map.get(&forward), Some(&"test 1".into()));
        assert_eq!(map.get(&reverse), Some(&"test 1".into()));
        assert_eq!(map.get(&unrelated), None);

        assert_eq!(map.insert(reverse.clone(), "test 2".into()), Some("test 1".into()));
        assert_eq!(map.insert(unrelated.clone(), "test 3".into()), None);
        assert_eq!(map.get(&forward), Some(&"test 2".into()));
        assert_eq!(map.get(&unrelated), Some(&"test 3".into()));
    }
}
