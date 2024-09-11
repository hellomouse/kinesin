use std::collections::HashMap;
use std::fmt::Display;
use std::mem;
use std::net::IpAddr;

use kinesin_rdt::common::ring_buffer::RingBuf;
use tracing::debug;
use tracing::warn;

use crate::connection::Connection;
use crate::connection::ConnectionState;
use crate::connection::Direction;
use crate::serialized::PacketExtra;
use crate::ConnectionHandler;
use crate::TcpMeta;

// https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
pub const IPPROTO_TCP: u8 = 6;
pub const IPPROTO_UDP: u8 = 17;

#[derive(Debug, Clone)]
pub struct Flow {
    pub proto: u8,
    pub src_addr: IpAddr,
    pub src_port: u16,
    pub dst_addr: IpAddr,
    pub dst_port: u16,
}

impl Flow {
    /// reverse source/destination in place
    pub fn reverse(&mut self) {
        mem::swap(&mut self.src_addr, &mut self.dst_addr);
        mem::swap(&mut self.src_port, &mut self.dst_port);
    }

    /// reverse source/destination, returning new instance
    pub fn reversed(&self) -> Self {
        Self {
            proto: self.proto,
            src_addr: self.dst_addr,
            src_port: self.dst_port,
            dst_addr: self.src_addr,
            dst_port: self.src_port,
        }
    }

    /// compare to TcpMeta
    pub fn compare_tcp_meta(&self, other: &TcpMeta) -> FlowCompare {
        self.compare(&other.into())
    }

    /// compare to other
    pub fn compare(&self, other: &Self) -> FlowCompare {
        if self.proto != other.proto {
            FlowCompare::None
        } else if self.src_addr == other.src_addr
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

impl From<&TcpMeta> for Flow {
    fn from(value: &TcpMeta) -> Self {
        Flow {
            proto: IPPROTO_TCP,
            src_addr: value.src_addr,
            src_port: value.src_port,
            dst_addr: value.dst_addr,
            dst_port: value.dst_port,
        }
    }
}

impl Display for Flow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        macro_rules! fmt_addr {
            ($addr:expr) => {
                match $addr {
                    IpAddr::V4(addr) => addr.fmt(f)?,
                    IpAddr::V6(addr) => {
                        write!(f, "[")?;
                        addr.fmt(f)?;
                        write!(f, "]")?;
                    }
                }
            };
        }
        match self.proto {
            IPPROTO_TCP => write!(f, "tcp/")?,
            IPPROTO_UDP => write!(f, "udp/")?,
            proto => write!(f, "{proto}/")?,
        }
        fmt_addr!(self.src_addr);
        write!(f, ":{} -> ", self.src_port)?;
        fmt_addr!(self.dst_addr);
        write!(f, ":{}", self.dst_port)?;
        Ok(())
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

impl FlowCompare {
    /// get direction from compare, or None
    pub fn to_direction(&self) -> Option<Direction> {
        match self {
            FlowCompare::Forward => Some(Direction::Forward),
            FlowCompare::Reverse => Some(Direction::Reverse),
            FlowCompare::None => None,
        }
    }
}

impl PartialEq for Flow {
    fn eq(&self, other: &Self) -> bool {
        self.compare(other) != FlowCompare::None
    }
}

impl Eq for Flow {}

impl std::hash::Hash for Flow {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.proto.hash(state);
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
pub struct FlowTable<H: ConnectionHandler>
where
    H::InitialData: Clone,
{
    /// map holding flows by tuple
    pub map: HashMap<Flow, Connection<H>>,
    /// retired connections (usually closed)
    // hahahahaha watch this explode
    pub retired: RingBuf<Connection<H>>,
    /// whether retired connections should be saved
    pub save_retired: bool,
    /// initial data for ConnectionHandler
    pub handler_init_data: H::InitialData,
}

/// result of FlowTable::handle_packet_direct
pub enum HandlePacketResult {
    /// packet successfully processed
    Ok,
    /// packet ignored, possibly because it was a duplicate
    Dropped,
    /// flow not found in hash table, data returned
    NotFound,
    /// connection fatally desynchronized, data returned
    Desync,
}

impl<H: ConnectionHandler> FlowTable<H>
where
    H::InitialData: Clone,
{
    /// create new instance
    pub fn new(handler_init_data: H::InitialData) -> Self {
        Self {
            map: HashMap::new(),
            retired: RingBuf::new(),
            save_retired: false,
            handler_init_data,
        }
    }

    /// handle a packet, creating a flow if necessary
    pub fn handle_packet(
        &mut self,
        meta: &TcpMeta,
        data: &[u8],
        extra: &PacketExtra,
    ) -> Result<bool, H::ConstructError> {
        match self.handle_packet_direct(meta, data, extra) {
            HandlePacketResult::Ok => Ok(true),
            HandlePacketResult::Dropped => Ok(false),
            HandlePacketResult::NotFound => {
                // create the flow, then process again
                self.create_flow(meta.into(), self.handler_init_data.clone())?;
                match self.handle_packet_direct(meta, data, extra) {
                    HandlePacketResult::Ok => Ok(true),
                    HandlePacketResult::Dropped => Ok(false),
                    _ => unreachable!("result not possible"),
                }
            }
            HandlePacketResult::Desync => {
                // remove flow, then recreate and try again
                debug!("handle_packet: got desync, recreating flow");
                let flow: Flow = meta.into();
                self.retire_flow(flow.clone());
                self.create_flow(flow, self.handler_init_data.clone())?;
                match self.handle_packet_direct(meta, data, extra) {
                    HandlePacketResult::Ok => Ok(true),
                    HandlePacketResult::Dropped => Ok(false),
                    _ => unreachable!("result not possible"),
                }
            }
        }
    }

    /// handle a packet, return Err if flow does not exist (and return args)
    pub fn handle_packet_direct(
        &mut self,
        meta: &TcpMeta,
        data: &[u8],
        extra: &PacketExtra,
    ) -> HandlePacketResult {
        let flow = meta.into();
        let did_something;
        match self.map.get_mut(&flow) {
            Some(conn) => {
                did_something = conn.handle_packet(meta, data, extra);
                match conn.conn_state {
                    // remove flow if connection is no more
                    ConnectionState::Closed => self.retire_flow(flow),
                    ConnectionState::Desync => {
                        return HandlePacketResult::Desync;
                    }
                    _ => {}
                }
                if did_something {
                    HandlePacketResult::Ok
                } else {
                    HandlePacketResult::Dropped
                }
            }
            None => HandlePacketResult::NotFound,
        }
    }

    /// create flow
    pub fn create_flow(
        &mut self,
        flow: Flow,
        init_data: H::InitialData,
    ) -> Result<Option<Connection<H>>, H::ConstructError> {
        let conn = Connection::new(flow.clone(), init_data)?;
        debug!("new flow: {} {flow}", conn.uuid);
        Ok(self.map.insert(flow, conn))
    }

    pub fn retire_flow(&mut self, flow: Flow) {
        let Some(mut conn) = self.map.remove(&flow) else {
            warn!("retire_flow called on non-existent flow?: {flow}");
            return;
        };

        debug!("remove flow: {} {flow}", conn.uuid);
        conn.will_retire();
        if self.save_retired {
            self.retired.push_back(conn);
        }
    }

    /// close flowtable and retire all flows
    pub fn close(&mut self) {
        debug!("flowtable closing");
        for (flow, mut conn) in self.map.drain() {
            debug!("remove flow: {} {flow}", conn.uuid);
            conn.will_retire();
            if self.save_retired {
                self.retired.push_back(conn);
            }
        }
    }
}

#[cfg(test)]
mod test {
    use std::collections::HashMap;
    use std::net::Ipv4Addr;

    use super::{Flow, IPPROTO_TCP};

    #[test]
    fn hash_map() {
        let forward = Flow {
            proto: IPPROTO_TCP,
            src_addr: Ipv4Addr::new(10, 3, 160, 24).into(),
            src_port: 35619,
            dst_addr: Ipv4Addr::new(1, 1, 1, 1).into(),
            dst_port: 53,
        };
        let reverse = Flow {
            proto: IPPROTO_TCP,
            src_addr: forward.dst_addr,
            src_port: forward.dst_port,
            dst_addr: forward.src_addr,
            dst_port: forward.src_port,
        };
        let unrelated = Flow {
            proto: IPPROTO_TCP,
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
