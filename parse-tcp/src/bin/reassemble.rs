use std::fs::File;
use std::io::BufWriter;
use std::io::Write;
use std::ops::Range;

use eyre::{eyre, Context};
use parse_tcp::connection::{Connection, Direction};
use parse_tcp::flow_table::FlowTable;
use parse_tcp::parser::{ParseLayer, Parser};
use parse_tcp::stream::{SegmentInfo, SegmentType};
use parse_tcp::{initialize_logging, ConnectionHandler, PacketExtra};
use pcap_parser::traits::PcapReaderIterator;
use pcap_parser::{LegacyPcapReader, Linktype, PcapBlockOwned, PcapError};
use tracing::info;

/*
fn dump_as_ascii(buf: &[u8]) {
    let mut writer = BufWriter::new(std::io::stdout());
    buf
        .iter()
        .copied()
        .flat_map(std::ascii::escape_default)
        .for_each(|b| {
            writer.write_all(&[b]).expect("failed write");
        });
    let _ = writer.write_all(b"\n");
}
*/

fn dump_as_readable_ascii(buf: &[u8]) {
    let mut writer = BufWriter::new(std::io::stdout());
    buf.iter().copied().map(|v| {
        if (b' '..=b'~').contains(&v) || v == b'\n' {
            v
        } else {
            b'.'
        }
    }).for_each(|v| writer.write_all(&[v]).expect("failed write"));
    let _ = writer.write_all(b"\n");
}

struct DumpHandler {
    gaps: Vec<Range<u64>>,
    segments: Vec<SegmentInfo>,
    buf: Vec<u8>,
}

impl DumpHandler {
    fn do_something(&mut self, connection: &mut Connection<Self>, direction: Direction) {
        self.gaps.clear();
        self.segments.clear();
        self.buf.clear();
        // indiscriminately dump everything to stdout
        let mut flow = connection.forward_flow.clone();
        if direction == Direction::Reverse {
            flow.reverse();
        }
        info!("{} id {}", flow, connection.uuid);
        let stream = connection.get_stream(direction);
        let dump_len = if stream.readable_buffered_length() > 0 {
            stream.readable_buffered_length()
        } else {
            stream.total_buffered_length().min(128 << 10)
        };
        let end_offset = stream.buffer_start() + dump_len as u64;
        info!("requesting length {dump_len}");
        stream.read_next(end_offset, &mut self.segments, &mut self.gaps, |slice| {
            let (a, b) = slice.as_slices();
            self.buf.extend_from_slice(a);
            if let Some(b) = b {
                self.buf.extend_from_slice(b);
            }
        });
        info!("gaps (length {})", self.gaps.len());
        for gap in &self.gaps {
            info!(" gap {} -> {}", gap.start, gap.end);
        }
        info!("segments (length {})", self.segments.len());
        for segment in &self.segments {
            info!(" offset {}", segment.offset);
            match segment.data {
                SegmentType::Data { len, is_retransmit } => {
                    info!(" type: data");
                    info!("  len {len}, retransmit {is_retransmit}");
                }
                SegmentType::Ack { window } => {
                    info!(" type: ack");
                    info!("  window: {window}");
                }
                SegmentType::Fin { end_offset } => {
                    info!(" type: fin");
                    info!("  end offset: {end_offset}");
                }
            }
        }
        info!("data (length {})", self.buf.len());
        dump_as_readable_ascii(&self.buf);
    }
}

impl ConnectionHandler for DumpHandler {
    fn new(_conn: &mut Connection<Self>) -> Self {
        DumpHandler {
            gaps: Vec::new(),
            segments: Vec::new(),
            buf: Vec::new(),
        }
    }

    fn data_received(&mut self, connection: &mut Connection<Self>, direction: Direction) {
        let stream = connection.get_stream(direction);
        if stream.readable_buffered_length() >= 64 << 10
            || stream.total_buffered_length() >= 1 << 20
        {
            self.do_something(connection, direction);
        }
    }

    fn will_retire(&mut self, connection: &mut Connection<Self>) {
        self.do_something(connection, Direction::Forward);
        self.do_something(connection, Direction::Reverse);
    }
}

fn main() -> eyre::Result<()> {
    initialize_logging();
    info!("Hello, world!");

    let file_name = std::env::args()
        .nth(1)
        .ok_or_else(|| eyre!("no filename provided"))?;
    let file = File::open(file_name).wrap_err("cannot open file")?;
    let mut pcap_reader =
        LegacyPcapReader::new(65536, file).wrap_err("failed to create LegacyPcapReader")?;
    let mut parser = Parser::new();
    let mut flowtable: FlowTable<DumpHandler> = FlowTable::new();
    let mut packet_counter = 0u64;
    loop {
        match pcap_reader.next() {
            Ok((offset, block)) => {
                match block {
                    PcapBlockOwned::LegacyHeader(hdr) => {
                        info!("pcap linktype: {:?}", hdr.network);
                        let layer = match hdr.network {
                            Linktype::ETHERNET => ParseLayer::Link,
                            Linktype::RAW => ParseLayer::IP,
                            Linktype::IPV4 => ParseLayer::IP,
                            Linktype::IPV6 => ParseLayer::IP,
                            Linktype::NULL => ParseLayer::BsdLoopback,
                            _ => eyre::bail!("pcap header: unknown link type {:?}", hdr.network),
                        };
                        parser.layer = layer;
                    }
                    PcapBlockOwned::Legacy(packet) => {
                        let index = packet_counter;
                        packet_counter += 1;
                        let extra = PacketExtra::LegacyPcap {
                            index,
                            ts_sec: packet.ts_sec,
                            ts_usec: packet.ts_usec,
                        };

                        if let Some((meta, data)) = parser.parse_packet(packet.data) {
                            flowtable.handle_packet(meta, data, extra);
                        };
                    }
                    PcapBlockOwned::NG(_) => unreachable!("read pcapng block in plain pcap"),
                }
                pcap_reader.consume(offset);
            }
            Err(PcapError::Eof) => break,
            Err(PcapError::Incomplete) => {
                match pcap_reader.refill() {
                    Ok(()) => {}
                    // only valid result is ReadError
                    Err(PcapError::ReadError) => {
                        eyre::bail!("read error occured while reading pcap");
                    }
                    _ => unreachable!(),
                }
            }
            Err(PcapError::HeaderNotRecognized) => {
                eyre::bail!("header not recognized (invalid pcap file?)");
            }
            Err(PcapError::NomError(_, kind) | PcapError::OwnedNomError(_, kind)) => {
                eyre::bail!("error parsing pcap (nom): {kind:?}");
            }
            Err(PcapError::ReadError) => {
                eyre::bail!("read error occured while reading pcap");
            }
        }
    }

    flowtable.close();
    Ok(())
}
