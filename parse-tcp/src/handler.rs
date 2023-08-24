use std::convert::Infallible;
use std::fs::File;
use std::io::{BufWriter, Seek, SeekFrom, Write};
use std::net::IpAddr;
use std::ops::Range;
use std::path::PathBuf;
use std::sync::Arc;

use eyre::Context;
use parking_lot::Mutex;
use serde::Serialize;
use tracing::{debug, info, trace};
use uuid::Uuid;

use crate::connection::{Connection, Direction};
use crate::flow_table::Flow;
use crate::stream::{SegmentInfo, SegmentType};
use crate::{ConnectionHandler, PacketExtra};

pub fn dump_as_readable_ascii(buf: &[u8], newline: bool) {
    let mut writer = BufWriter::new(std::io::stdout());
    buf.iter()
        .copied()
        .map(|v| {
            if (b' '..=b'~').contains(&v) || v == b'\n' {
                v
            } else {
                b'.'
            }
        })
        .for_each(|v| writer.write_all(&[v]).expect("failed write"));
    if newline {
        let _ = writer.write_all(b"\n");
    }
}

/// ConnectionHandler to dump data to stdout
pub struct DumpHandler {
    pub gaps: Vec<Range<u64>>,
    pub segments: Vec<SegmentInfo>,
    pub buf: Vec<u8>,
    pub forward_has_data: bool,
    pub reverse_has_data: bool,
}

impl DumpHandler {
    pub fn dump_stream_segments(&self) {
        info!("segments (length {})", self.segments.len());
        for segment in &self.segments {
            info!("  offset: {}", segment.offset);
            info!("  reverse acked: {}", segment.reverse_acked);
            match segment.data {
                SegmentType::Data { len, is_retransmit } => {
                    info!("  type: data");
                    info!("    len {len}, retransmit {is_retransmit}");
                }
                SegmentType::Ack { window } => {
                    info!("  type: ack");
                    info!("    window: {window}");
                }
                SegmentType::Fin { end_offset } => {
                    info!("  type: fin");
                    info!("    end offset: {end_offset}");
                }
            }
        }
    }

    pub fn dump_stream(
        &mut self,
        connection: &mut Connection<Self>,
        direction: Direction,
        dump_len: usize,
    ) {
        self.gaps.clear();
        self.segments.clear();
        self.buf.clear();
        // indiscriminately dump everything to stdout
        let mut flow = connection.forward_flow.clone();
        if direction == Direction::Reverse {
            flow.reverse();
        }
        let uuid = connection.uuid;
        let stream = connection.get_stream(direction);

        let start_offset = stream.buffer_start();
        let end_offset = start_offset + dump_len as u64;
        if dump_len > 0 {
            trace!("requesting {dump_len} bytes for direction {direction}");
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
            self.dump_stream_segments();

            info!("data (length {})", self.buf.len());
            println!("\n====================\n{} ({})", flow, uuid);
            println!("  offset: {start_offset}");
            println!("  length: {dump_len}\n");
            if !self.gaps.is_empty() {
                let gaps_len: u64 = self.gaps.iter().map(|r| r.end - r.start).sum();
                println!("  gap bytes: {gaps_len}");
            }
            dump_as_readable_ascii(&self.buf, true);
        } else {
            // read segments only
            stream.read_segments_until(end_offset, &mut self.segments);
            info!("no new data, dumping segments only");
            self.dump_stream_segments();
        }
    }

    pub fn write_remaining(&mut self, connection: &mut Connection<Self>, direction: Direction) {
        debug!(
            "connection {} direction {direction} writing remaining segments",
            connection.uuid
        );
        let remaining = connection.get_stream(direction).total_buffered_length();
        self.dump_stream(connection, direction, remaining);
    }
}

impl ConnectionHandler for DumpHandler {
    type InitialData = ();
    type ConstructError = Infallible;
    fn new(_init: (), _conn: &mut Connection<Self>) -> Result<Self, Infallible> {
        Ok(DumpHandler {
            gaps: Vec::new(),
            segments: Vec::new(),
            buf: Vec::new(),
            forward_has_data: false,
            reverse_has_data: false,
        })
    }

    fn data_received(&mut self, connection: &mut Connection<Self>, direction: Direction) {
        let (fwd_data, rev_data) = match direction {
            Direction::Forward => (&mut self.forward_has_data, &mut self.reverse_has_data),
            Direction::Reverse => (&mut self.reverse_has_data, &mut self.forward_has_data),
        };
        let fwd_readable_len = connection.get_stream(direction).readable_buffered_length();
        *fwd_data = fwd_readable_len > 0;

        // dump reverse stream buffer if it has data
        if *rev_data {
            let rev_stream = connection.get_stream(direction.swap());
            let readable = rev_stream.readable_buffered_length();
            if readable > 0 {
                trace!("reverse stream has data, will dump");
                self.dump_stream(connection, direction.swap(), readable);
            }
        }

        // dump forward stream if limits hit
        let fwd_stream = connection.get_stream(direction);
        if fwd_readable_len > 64 << 10 || fwd_stream.segments_info.len() > 16 << 10 {
            trace!("forward stream exceeded threshold, will dump");
            self.dump_stream(connection, direction, fwd_readable_len);
        } else if fwd_stream.total_buffered_length() > 256 << 10 {
            trace!("forward stream exceeded total buffer size threshold, will dump");
            self.dump_stream(connection, direction, 128 << 10);
        }
    }

    fn will_retire(&mut self, connection: &mut Connection<Self>) {
        self.write_remaining(connection, Direction::Forward);
        self.write_remaining(connection, Direction::Reverse);
    }
}

#[derive(Serialize)]
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

/// shared state for DirectoryOutputHandler
pub struct DirectoryOutputSharedInfoInner {
    pub base_dir: PathBuf,
    pub conn_info_file: Mutex<File>,
}

impl DirectoryOutputSharedInfoInner {
    /// create with output path
    pub fn new(base_dir: PathBuf) -> std::io::Result<Arc<Self>> {
        let mut conn_info_file = File::create(base_dir.join("connections.json"))?;
        conn_info_file.write_all(b"[\n")?;
        Ok(Arc::new(DirectoryOutputSharedInfoInner {
            base_dir,
            conn_info_file: Mutex::new(conn_info_file),
        }))
    }

    /// write connection info
    pub fn record_conn_info(self: &Arc<Self>, uuid: Uuid, flow: &Flow) -> std::io::Result<()> {
        let mut serialized = serde_json::to_string(&ConnInfo::new(uuid, flow))
            .expect("failed to serialize ConnInfo");
        serialized += ",\n";
        let mut file = self.conn_info_file.lock();
        file.write_all(serialized.as_bytes())
    }

    /// close connection info file
    pub fn close(self) -> std::io::Result<()> {
        let mut conn_info_file = self.conn_info_file.into_inner();
        let current_pos = conn_info_file.stream_position()?;
        if current_pos > 2 {
            // overwrite trailing comma and close array
            conn_info_file.seek(SeekFrom::Current(-2))?;
            conn_info_file.write_all(b"\n]\n")?;
        } else {
            // no connections, just close the array
            conn_info_file.write_all(b"]\n")?;
        }
        Ok(())
    }
}

type DirectoryOutputSharedInfo = Arc<DirectoryOutputSharedInfoInner>;

#[derive(Serialize)]
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
        }
    }
}

/// ConnectionHandler to write data to a directory
pub struct DirectoryOutputHandler {
    pub shared_info: DirectoryOutputSharedInfo,
    pub id: Uuid,
    pub gaps: Vec<Range<u64>>,
    pub segments: Vec<SegmentInfo>,

    pub forward_data: File,
    pub forward_segments: File,
    pub reverse_data: File,
    pub reverse_segments: File,
}

impl DirectoryOutputHandler {
    pub fn write_stream_data(
        &mut self,
        connection: &mut Connection<Self>,
        direction: Direction,
        dump_len: usize,
    ) -> std::io::Result<()> {
        self.gaps.clear();
        self.segments.clear();

        let (data_file, mut segments_file) = match direction {
            Direction::Forward => (
                &mut self.forward_data,
                BufWriter::new(&mut self.forward_segments),
            ),
            Direction::Reverse => (
                &mut self.reverse_data,
                BufWriter::new(&mut self.reverse_segments),
            ),
        };

        let stream = connection.get_stream(direction);
        if dump_len > 0 {
            trace!("write_stream_data: requesting {dump_len} bytes from stream for {direction}");
            let start_offset = stream.buffer_start();
            let end_offset = start_offset + dump_len as u64;
            stream
                .read_next(end_offset, &mut self.segments, &mut self.gaps, |slice| {
                    let (a, b) = slice.as_slices();
                    trace!("write_stream_data: writing {} data bytes", a.len());
                    data_file.write_all(a)?;
                    if let Some(b) = b {
                        trace!("write_stream_data: writing {} data bytes", b.len());
                        data_file.write_all(b)?;
                    }
                    Result::<(), std::io::Error>::Ok(())
                })
                .expect("read_next cannot fulfill range")?;
        } else if !stream.segments_info.is_empty() {
            // only dump remaining segments
            stream.read_segments_until(stream.buffer_start(), &mut self.segments);
        } else {
            // nothing to do
            return Ok(());
        }

        // write gaps and segments in order
        let mut gaps_iter = self.gaps.iter().peekable();
        let mut segments_iter = self.segments.iter().peekable();
        loop {
            enum WhichNext {
                Gap,
                Segment,
            }
            // figure out which to write next
            let which = match (gaps_iter.peek(), segments_iter.peek()) {
                (None, None) => break,
                (None, Some(_)) => WhichNext::Segment,
                (Some(_), None) => WhichNext::Gap,
                (Some(&gap), Some(&segment)) => {
                    if gap.start < segment.offset {
                        WhichNext::Gap
                    } else {
                        WhichNext::Segment
                    }
                }
            };

            // serialize and write
            match which {
                WhichNext::Gap => {
                    let gap = gaps_iter.next().unwrap();
                    let info = SerializedSegment::new_gap(gap.start, gap.end - gap.start);
                    serde_json::to_writer(&mut segments_file, &info)?;
                    segments_file.write_all(b"\n")?;
                }
                WhichNext::Segment => {
                    let segment = segments_iter.next().unwrap();
                    let info: SerializedSegment = segment.into();
                    serde_json::to_writer(&mut segments_file, &info)?;
                    segments_file.write_all(b"\n")?;
                }
            }
        }

        self.gaps.clear();
        self.segments.clear();
        Ok(())
    }

    pub fn write_remaining(
        &mut self,
        connection: &mut Connection<Self>,
        direction: Direction,
    ) -> std::io::Result<()> {
        debug!(
            "connection {} direction {direction} writing remaining segments",
            connection.uuid
        );
        let remaining = connection.get_stream(direction).total_buffered_length();
        self.write_stream_data(connection, direction, remaining)
    }
}

macro_rules! log_error {
    ($result:expr, $what:expr) => {
        if let Err(e) = $result {
            ::tracing::error!(concat!($what, ": {:?}"), e);
        }
    };
}

impl ConnectionHandler for DirectoryOutputHandler {
    type InitialData = DirectoryOutputSharedInfo;
    type ConstructError = eyre::Report;
    fn new(
        shared_info: Self::InitialData,
        connection: &mut Connection<Self>,
    ) -> eyre::Result<Self> {
        let id = connection.uuid;
        let base_dir = &shared_info.base_dir;
        let forward_data = File::create(base_dir.join(format!("{id}.f.data")))
            .wrap_err("creating forward data file")?;
        let forward_segments = File::create(base_dir.join(format!("{id}.f.jsonl")))
            .wrap_err("creating forward segments file")?;
        let reverse_data = File::create(base_dir.join(format!("{id}.r.data")))
            .wrap_err("creating reverse data file")?;
        let reverse_segments = File::create(base_dir.join(format!("{id}.r.jsonl")))
            .wrap_err("creating reverse segments file")?;

        Ok(DirectoryOutputHandler {
            shared_info,
            id,
            gaps: Vec::new(),
            segments: Vec::new(),
            forward_data,
            forward_segments,
            reverse_data,
            reverse_segments,
        })
    }

    fn handshake_done(&mut self, connection: &mut Connection<Self>) {
        log_error!(
            self.shared_info
                .record_conn_info(connection.uuid, &connection.forward_flow),
            "failed to write connection info"
        );
    }

    fn data_received(&mut self, connection: &mut Connection<Self>, direction: Direction) {
        let stream = connection.get_stream(direction);
        let readable_len = stream.readable_buffered_length();
        if readable_len > 64 << 10 || stream.segments_info.len() > 16 << 10 {
            log_error!(
                self.write_stream_data(connection, direction, readable_len),
                "failed to write stream data"
            );
        } else if stream.total_buffered_length() > 256 << 10 {
            log_error!(
                self.write_stream_data(connection, direction, 128 << 10),
                "failed to write stream data"
            );
        }
    }

    fn will_retire(&mut self, connection: &mut Connection<Self>) {
        log_error!(
            self.write_remaining(connection, Direction::Forward),
            "failed to write stream data"
        );
        log_error!(
            self.write_remaining(connection, Direction::Reverse),
            "failed to write stream data"
        );
    }
}
