use std::collections::HashMap;
use std::mem;
use std::net::IpAddr;

use crate::connection::Connection;
use crate::TcpMeta;

#[derive(Debug, Clone)]
pub struct Flow {
    pub src_addr: IpAddr,
    pub src_port: u16,
    pub dst_addr: IpAddr,
    pub dst_port: u16,
}

impl Flow {
    /// reverse source/destination
    pub fn reverse(&mut self) {
        mem::swap(&mut self.src_addr, &mut self.dst_addr);
        mem::swap(&mut self.src_port, &mut self.dst_port);
    }

    /// compare to TcpMeta
    pub fn compare_tcp_meta(&self, other: &TcpMeta) -> FlowCompare {
        self.compare(&other.clone().into())
    }

    /// compare to other
    pub fn compare(&self, other: &Self) -> FlowCompare {
        if self.src_addr == other.src_addr
            && self.dst_addr == other.dst_addr
            && self.src_port == other.src_port
            && self.dst_port == other.dst_port
        {
            // exact match
            FlowCompare::Forward
        } else if self.src_addr == other.dst_addr
            && self.dst_addr == other.src_addr
            && self.src_port == other.dst_port
            && self.dst_port == other.src_port
        {
            // reverse direction
            FlowCompare::Reverse
        } else {
            FlowCompare::None
        }
    }
}

impl From<TcpMeta> for Flow {
    fn from(value: TcpMeta) -> Self {
        Flow {
            src_addr: value.src_addr,
            src_port: value.src_port,
            dst_addr: value.dst_addr,
            dst_port: value.dst_port,
        }
    }
}

/// result of FlowId::compare
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowCompare {
    /// identical to other
    Forward,
    /// reversed of other
    Reverse,
    /// no relation
    None,
}

impl PartialEq for Flow {
    fn eq(&self, other: &Self) -> bool {
        self.compare(other) != FlowCompare::None
    }
}

impl Eq for Flow {}

impl std::hash::Hash for Flow {
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

/// a table of TCP connections
pub struct FlowTable {
    /// map holding flows by tuple
    pub map: HashMap<Flow, Connection>,
    /// retired connections (usually closed)
    pub retired: Vec<Connection>,
}

#[cfg(test)]
mod test {
    use std::collections::HashMap;
    use std::net::Ipv4Addr;

    use super::Flow;

    #[test]
    fn hash_map() {
        let forward = Flow {
            src_addr: Ipv4Addr::new(10, 3, 160, 24).into(),
            src_port: 35619,
            dst_addr: Ipv4Addr::new(1, 1, 1, 1).into(),
            dst_port: 53,
        };
        let reverse = Flow {
            src_addr: forward.dst_addr,
            src_port: forward.dst_port,
            dst_addr: forward.src_addr,
            dst_port: forward.src_port,
        };
        let unrelated = Flow {
            src_addr: Ipv4Addr::new(10, 3, 160, 24).into(),
            src_port: 35619,
            dst_addr: Ipv4Addr::new(8, 8, 8, 8).into(),
            dst_port: 53,
        };
        assert_eq!(forward, reverse);
        assert_ne!(forward, unrelated);

        let mut map: HashMap<Flow, String> = HashMap::new();
        map.insert(forward.clone(), "test 1".into());
        assert_eq!(map.get(&forward), Some(&"test 1".into()));
        assert_eq!(map.get(&reverse), Some(&"test 1".into()));
        assert_eq!(map.get(&unrelated), None);

        assert_eq!(
            map.insert(reverse.clone(), "test 2".into()),
            Some("test 1".into())
        );
        assert_eq!(map.insert(unrelated.clone(), "test 3".into()), None);
        assert_eq!(map.get(&forward), Some(&"test 2".into()));
        assert_eq!(map.get(&unrelated), Some(&"test 3".into()));
    }
}
