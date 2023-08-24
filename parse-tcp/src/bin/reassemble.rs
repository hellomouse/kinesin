use std::fs::File;
use std::io::Read;
use std::path::PathBuf;

use clap::Parser as ClapParser;
use eyre::Context;
use parse_tcp::flow_table::FlowTable;
use parse_tcp::handler::{DirectoryOutputHandler, DirectoryOutputSharedInfo, DumpHandler};
use parse_tcp::parser::{ParseLayer, TcpParser};
use parse_tcp::{initialize_logging, PacketExtra, TcpMeta};
use pcap_parser::traits::PcapReaderIterator;
use pcap_parser::{LegacyPcapReader, Linktype, PcapBlockOwned, PcapError};
use tracing::{debug, error, info, warn};

const PCAP_READER_BUFFER_SIZE: usize = 4 << 20; // 4 MB

/// Reassemble TCP streams in a packet capture
#[derive(ClapParser, Debug)]
#[command(about, version)]
struct Args {
    /// Input capture file, supports pcap only (not yet pcapng)
    #[arg(short = 'f', long)]
    input: PathBuf,
    /// Directory to write stream data. If not provided, will dump to stdout.
    #[arg(short = 'd', long)]
    output_dir: Option<PathBuf>,
}

fn main() -> eyre::Result<()> {
    initialize_logging();
    info!("Hello, world!");
    let args = Args::parse();
    let file = File::open(args.input).wrap_err("cannot open file")?;
    if let Some(out_dir) = args.output_dir {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        unsafe {
            info!("attempting to raise file limit");
            match i_want_more_files(1 << 20) {
                Ok(n) => info!("raised file limit to {n} files"),
                Err(e) => warn!("failed to raise file limit: {e:?}"),
            }
        }
        write_to_dir(file, out_dir)?;
    } else {
        dump_to_stdout(file)?;
    }
    Ok(())
}

fn dump_to_stdout(file: File) -> eyre::Result<()> {
    let mut flowtable: FlowTable<DumpHandler> = FlowTable::new(());

    parse_packets(file, |meta, data, extra| {
        let _ = flowtable.handle_packet(&meta, data, &extra);
        Ok(())
    })?;

    flowtable.close();
    Ok(())
}

fn write_to_dir(file: File, out_dir: PathBuf) -> eyre::Result<()> {
    let (shared_info, errors_rx) =
        DirectoryOutputSharedInfo::new(out_dir).wrap_err("writing connections information file")?;
    let mut flowtable: FlowTable<DirectoryOutputHandler> = FlowTable::new(shared_info.clone());

    parse_packets(file, |meta, data: &[u8], extra| {
        flowtable.handle_packet(&meta, data, &extra)?;
        if let Ok(e) = errors_rx.try_recv() {
            return Err(e);
        }
        Ok(())
    })?;

    flowtable.close();
    drop(flowtable);
    shared_info.close()?;
    Ok(())
}

fn parse_packets(
    reader: impl Read,
    mut handler: impl FnMut(TcpMeta, &[u8], PacketExtra) -> eyre::Result<()>,
) -> eyre::Result<()> {
    let mut parser = TcpParser::new();
    let mut packet_counter = 0u64;
    read_pcap_legacy(reader, |block| match block {
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
            Ok(())
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
                handler(meta, data, extra)?;
            };
            Ok(())
        }
        PcapBlockOwned::NG(_) => unreachable!("read pcapng block in plain pcap"),
    })
}

fn read_pcap_legacy(
    reader: impl Read,
    mut handler: impl FnMut(PcapBlockOwned<'_>) -> eyre::Result<()>,
) -> eyre::Result<()> {
    let mut pcap_reader = LegacyPcapReader::new(PCAP_READER_BUFFER_SIZE, reader)
        .wrap_err("failed to create LegacyPcapReader")?;
    let mut did_refill = false;
    loop {
        match pcap_reader.next() {
            Ok((offset, block)) => {
                did_refill = false;
                handler(block)?;
                pcap_reader.consume(offset);
            }
            Err(PcapError::Eof) => {
                debug!("eof");
                break;
            }
            Err(PcapError::UnexpectedEof) => {
                error!("unexpected eof while reading pcap");
                break;
            }
            Err(PcapError::Incomplete) => {
                if did_refill {
                    eyre::bail!("infinite loop in pcap_reader.refill()");
                }
                match pcap_reader.refill() {
                    Ok(()) => {
                        did_refill = true;
                    }
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
    Ok(())
}

/// raise RLIMIT_NOFILE so we can open more files
#[cfg(any(target_os = "linux", target_os = "macos"))]
unsafe fn i_want_more_files(more_files: u64) -> eyre::Result<u64> {
    macro_rules! raise_os_error {
        ($what:expr) => {
            let err = ::std::io::Error::last_os_error();
            return Err(::eyre::eyre!(err).wrap_err($what));
        };
    }
    let mut current_limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    let ret = libc::getrlimit(libc::RLIMIT_NOFILE, &mut current_limit);
    if ret < 0 {
        raise_os_error!("getrlimit(RLIMIT_NOFILE)");
    }
    let new_limit = libc::rlimit {
        rlim_cur: current_limit.rlim_max.min(more_files),
        rlim_max: current_limit.rlim_max,
    };
    let ret = libc::setrlimit(libc::RLIMIT_NOFILE, &new_limit);
    if ret < 0 {
        raise_os_error!("setrlimit(RLIMIT_NOFILE");
    }
    Ok(new_limit.rlim_cur)
}
