use std::net::IpAddr;

use etherparse::{InternetSlice, SlicedPacket, TcpOptionElement, TransportSlice};
use tracing::{debug, trace};

use crate::{TcpFlags, TcpMeta};

/// parses only TCP packets with etherparse
pub struct TcpParser {
    pub layer: ParseLayer,
    pub failed_parse: usize,
    pub ignored: usize,
}

impl TcpParser {
    pub fn new() -> Self {
        Self {
            layer: ParseLayer::Link,
            failed_parse: 0,
            ignored: 0,
        }
    }

    /// parse tcp packets into TcpMeta and data
    pub fn parse_packet<'a>(&mut self, data: &'a [u8]) -> Option<(TcpMeta, &'a [u8])> {
        let parse_result = match self.layer {
            ParseLayer::Link => SlicedPacket::from_ethernet(data),
            ParseLayer::IP => SlicedPacket::from_ip(data),
            // BSD loopback has 4 byte header before IP, remove it
            ParseLayer::BsdLoopback => SlicedPacket::from_ip(&data[4..]),
        };
        // ignore errors
        let Ok(parsed) = parse_result else {
            debug!("packet failed parse: {:?}", parse_result.unwrap_err());
            self.failed_parse += 1;
            return None;
        };
        let Some(internet_slice) = parsed.ip else {
            trace!("ignoring packet: no IP layer");
            self.ignored += 1;
            return None;
        };
        let Some(transport_slice) = parsed.transport else {
            trace!("ignoring packet: no transport layer");
            self.ignored += 1;
            return None;
        };
        let TransportSlice::Tcp(tcp_slice) = transport_slice else {
            trace!("ignoring packet: not tcp");
            self.ignored += 1;
            return None;
        };

        let (src_addr, dst_addr): (IpAddr, IpAddr) = match internet_slice {
            InternetSlice::Ipv4(v4, _ext) => {
                (v4.source_addr().into(), v4.destination_addr().into())
            }
            InternetSlice::Ipv6(v6, _ext) => {
                (v6.source_addr().into(), v6.destination_addr().into())
            }
        };

        let mut option_window_scale = None;
        let mut option_timestamp = None;
        for opt in tcp_slice.options_iterator() {
            match opt {
                Ok(TcpOptionElement::WindowScale(scale)) => {
                    option_window_scale = Some(scale);
                }
                Ok(TcpOptionElement::Timestamp(a, b)) => {
                    option_timestamp = Some((a, b));
                }
                // ignore all other options
                _ => {}
            }
        }

        let meta = TcpMeta {
            src_addr,
            src_port: tcp_slice.source_port(),
            dst_addr,
            dst_port: tcp_slice.destination_port(),
            seq_number: tcp_slice.sequence_number(),
            ack_number: tcp_slice.acknowledgment_number(),
            flags: TcpFlags {
                syn: tcp_slice.syn(),
                ack: tcp_slice.ack(),
                fin: tcp_slice.fin(),
                rst: tcp_slice.rst(),
            },
            window: tcp_slice.window_size(),
            option_window_scale,
            option_timestamp,
        };

        Some((meta, parsed.payload))
    }
}

impl Default for TcpParser {
    fn default() -> Self {
        Self::new()
    }
}

/// layer of input packets
pub enum ParseLayer {
    /// link layer (layer 2)
    Link,
    /// IP layer (layer 3)
    IP,
    /// BSD loopback (linktype 0/NULL)
    BsdLoopback,
}
