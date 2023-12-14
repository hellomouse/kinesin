use std::net::IpAddr;

use serde::{Serialize, Deserialize};
use uuid::Uuid;

use crate::flow_table::Flow;
use crate::stream::{SegmentInfo, SegmentType};

/// extra information that may be associated with the packet
#[derive(Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum PacketExtra {
    None,
    LegacyPcap {
        /// packet number
        index: u64,
        /// timestamp (seconds)
        ts_sec: u32,
        /// timestamp (microseconds)
        ts_usec: u32,
    },
}

#[derive(Serialize, Deserialize)]
pub struct ConnInfo {
    pub id: Uuid,
    pub src_addr: IpAddr,
    pub src_port: u16,
    pub dst_addr: IpAddr,
    pub dst_port: u16,
}

impl ConnInfo {
    pub fn new(uuid: Uuid, flow: &Flow) -> Self {
        ConnInfo {
            id: uuid,
            src_addr: flow.src_addr,
            src_port: flow.src_port,
            dst_addr: flow.dst_addr,
            dst_port: flow.dst_port,
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum SerializedSegment {
    #[serde(rename = "data")]
    Data {
        offset: u64,
        len: usize,
        is_retransmit: bool,
        reverse_acked: u64,
        #[serde(flatten)]
        extra: PacketExtra,
    },
    #[serde(rename = "ack")]
    Ack {
        offset: u64,
        window: usize,
        reverse_acked: u64,
        #[serde(flatten)]
        extra: PacketExtra,
    },
    #[serde(rename = "fin")]
    Fin {
        offset: u64,
        reverse_acked: u64,
        #[serde(flatten)]
        extra: PacketExtra,
    },
    #[serde(rename = "rst")]
    Rst {
        offset: u64,
        reverse_acked: u64,
        #[serde(flatten)]
        extra: PacketExtra,
    },
    #[serde(rename = "gap")]
    Gap { offset: u64, len: u64 },
}

impl SerializedSegment {
    pub fn new_gap(offset: u64, len: u64) -> Self {
        Self::Gap { offset, len }
    }
}

impl From<&SegmentInfo> for SerializedSegment {
    fn from(info: &SegmentInfo) -> Self {
        match info.data {
            SegmentType::Data { len, is_retransmit } => Self::Data {
                offset: info.offset,
                len,
                is_retransmit,
                reverse_acked: info.reverse_acked,
                extra: info.extra.clone(),
            },
            SegmentType::Ack { window } => Self::Ack {
                offset: info.offset,
                window,
                reverse_acked: info.reverse_acked,
                extra: info.extra.clone(),
            },
            SegmentType::Fin { end_offset } => Self::Fin {
                offset: end_offset,
                reverse_acked: info.reverse_acked,
                extra: info.extra.clone(),
            },
            SegmentType::Rst => Self::Rst {
                offset: info.offset,
                reverse_acked: info.reverse_acked,
                extra: info.extra.clone(),
            },
        }
    }
}
