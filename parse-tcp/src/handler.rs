use std::convert::Infallible;
use std::fs::File;
use std::io::{BufWriter, Seek, SeekFrom, Write};
use std::ops::Range;
use std::path::PathBuf;
use std::sync::Arc;

use eyre::Context;
use parking_lot::Mutex;
use tracing::{debug, info, trace};
use uuid::Uuid;

use crate::connection::{Connection, Direction};
use crate::flow_table::Flow;
use crate::serialized::{PacketExtra, ConnInfo, SerializedSegment};
use crate::stream::{SegmentInfo, SegmentType};
use crate::ConnectionHandler;

/// threshold for buffered readable bytes before writing out
const BUFFER_READABLE_THRESHOLD: usize = 64 << 10;
/// threshold for buffered segment info objects before writing out
const BUFFER_SEGMENTS_THRESHOLD: usize = 16 << 10;
/// threshold for total buffered bytes before writing out
const BUFFER_TOTAL_THRESHOLD: usize = 256 << 10;
/// how many bytes to advance when hitting BUFFER_TOTAL_THRESHOLD
const BUFFER_TOTAL_THRESHOLD_ADVANCE: usize = 64 << 10;

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
        debug!("segments (length {})", self.segments.len());
        for segment in &self.segments {
            debug!("  offset: {}", segment.offset);
            debug!("  reverse acked: {}", segment.reverse_acked);
            match segment.data {
                SegmentType::Data { len, is_retransmit } => {
                    debug!("  type: data");
                    debug!("    len {len}, retransmit {is_retransmit}");
                }
                SegmentType::Ack { window } => {
                    debug!("  type: ack");
                    debug!("    window: {window}");
                }
                SegmentType::Fin { end_offset } => {
                    debug!("  type: fin");
                    debug!("    end offset: {end_offset}");
                }
                SegmentType::Rst => {
                    debug!("  type: rst");
                }
            }
        }
    }

    pub fn dump_stream(
        &mut self,
        connection: &mut Connection<Self>,
        direction: Direction,
        maybe_dump_len: Option<usize>,
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

        let dump_len = if let Some(dump_len) = maybe_dump_len {
            debug_assert!(dump_len > 0);
            dump_len
        } else {
            // explicitly dump all remaining segments
            trace!("dumping remaining segments for direction {direction}");
            stream.read_segments_until(None, &mut self.segments);
            // dump everything remaining
            stream.total_buffered_length()
        };

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

            if !self.gaps.is_empty() {
                debug!("gaps (length {})", self.gaps.len());
                for gap in &self.gaps {
                    debug!(" gap {} -> {}", gap.start, gap.end);
                }
            }
            self.dump_stream_segments();

            debug!("data (length {})", self.buf.len());
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
            debug!("no new data, dumping segments only");
            self.dump_stream_segments();
        }
    }

    pub fn write_remaining(&mut self, connection: &mut Connection<Self>, direction: Direction) {
        debug!(
            "connection {} direction {direction} writing remaining segments",
            connection.uuid
        );
        self.dump_stream(connection, direction, None);
    }
}

impl ConnectionHandler for DumpHandler {
    type InitialData = ();
    type ConstructError = Infallible;
    fn new(_init: (), conn: &mut Connection<Self>) -> Result<Self, Infallible> {
        info!("new connection: {} ({})", conn.uuid, conn.forward_flow);
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
                self.dump_stream(connection, direction.swap(), Some(readable));
            }
        }

        // dump forward stream if limits hit
        let fwd_stream = connection.get_stream(direction);
        if fwd_readable_len > BUFFER_READABLE_THRESHOLD
            || fwd_stream.segments_info.len() > BUFFER_SEGMENTS_THRESHOLD
        {
            trace!("forward stream exceeded threshold, will dump");
            self.dump_stream(connection, direction, Some(fwd_readable_len));
        } else if fwd_stream.total_buffered_length() > BUFFER_TOTAL_THRESHOLD {
            trace!("forward stream exceeded total buffer size threshold, will dump");
            self.dump_stream(connection, direction, Some(BUFFER_TOTAL_THRESHOLD_ADVANCE));
        }
    }

    fn rst_received(
        &mut self,
        connection: &mut Connection<Self>,
        direction: Direction,
        _extra: PacketExtra,
    ) {
        debug!("{direction} ({}) received reset", connection.uuid);
    }

    fn will_retire(&mut self, connection: &mut Connection<Self>) {
        info!(
            "removing connection: {} ({})",
            connection.forward_flow, connection.uuid
        );
        self.write_remaining(connection, Direction::Forward);
        self.write_remaining(connection, Direction::Reverse);
    }
}

/// shared state for DirectoryOutputHandler
pub struct DirectoryOutputSharedInfoInner {
    pub base_dir: PathBuf,
    pub conn_info_file: Mutex<File>,
}

#[derive(Clone)]
pub struct DirectoryOutputSharedInfo {
    pub inner: Arc<DirectoryOutputSharedInfoInner>,
    pub errors: crossbeam_channel::Sender<eyre::Report>,
}

pub type ErrorReceiver = crossbeam_channel::Receiver<eyre::Report>;
impl DirectoryOutputSharedInfo {
    /// create with output path
    pub fn new(base_dir: PathBuf) -> std::io::Result<(Self, ErrorReceiver)> {
        let mut conn_info_file = File::create(base_dir.join("connections.json"))?;
        conn_info_file.write_all(b"[\n")?;
        let (error_tx, error_rx) = crossbeam_channel::unbounded();
        Ok((
            DirectoryOutputSharedInfo {
                inner: Arc::new(DirectoryOutputSharedInfoInner {
                    base_dir,
                    conn_info_file: Mutex::new(conn_info_file),
                }),
                errors: error_tx,
            },
            error_rx,
        ))
    }

    /// write connection info
    pub fn record_conn_info(&self, uuid: Uuid, flow: &Flow) -> std::io::Result<()> {
        let mut serialized = serde_json::to_string(&ConnInfo::new(uuid, flow))
            .expect("failed to serialize ConnInfo");
        serialized += ",\n";
        let mut file = self.inner.conn_info_file.lock();
        file.write_all(serialized.as_bytes())
    }

    /// close connection info file
    pub fn close(self) -> std::io::Result<()> {
        let mut conn_info_file = Arc::into_inner(self.inner)
            .unwrap()
            .conn_info_file
            .into_inner();
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

    /// run a closure, sending errors through the error channel
    pub fn capture_errors<T>(&self, func: impl FnOnce() -> eyre::Result<T>) -> Option<T> {
        match func() {
            Ok(r) => Some(r),
            Err(e) => {
                self.errors.send(e).expect("could not forward error");
                None
            }
        }
    }
}

/// stream files for DirectoryOutputHandler
pub struct DirectoryOutputHandlerFiles {
    pub forward_data: File,
    pub forward_segments: File,
    pub reverse_data: File,
    pub reverse_segments: File,
}

/// ConnectionHandler to write data to a directory
pub struct DirectoryOutputHandler {
    pub shared_info: DirectoryOutputSharedInfo,
    pub id: Uuid,
    pub gaps: Vec<Range<u64>>,
    pub segments: Vec<SegmentInfo>,
    /// whether we received the handshake_done event
    pub got_handshake_done: bool,
    pub files: Option<DirectoryOutputHandlerFiles>,
}

impl DirectoryOutputHandler {
    pub fn write_stream_data(
        &mut self,
        connection: &mut Connection<Self>,
        direction: Direction,
        maybe_dump_len: Option<usize>,
    ) -> std::io::Result<()> {
        self.gaps.clear();
        self.segments.clear();

        let files = self.files.as_mut().expect("files not available!");
        let (data_file, mut segments_file) = match direction {
            Direction::Forward => (
                &mut files.forward_data,
                BufWriter::new(&mut files.forward_segments),
            ),
            Direction::Reverse => (
                &mut files.reverse_data,
                BufWriter::new(&mut files.reverse_segments),
            ),
        };

        let stream = connection.get_stream(direction);
        let dump_len = if let Some(dump_len) = maybe_dump_len {
            debug_assert!(dump_len > 0);
            dump_len
        } else {
            // explicitly dump all remaining segments
            stream.read_segments_until(None, &mut self.segments);
            // dump everything remaining
            stream.total_buffered_length()
        };
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
        debug!(
            "connection created: {} ({})",
            connection.forward_flow, connection.uuid
        );
        Ok(DirectoryOutputHandler {
            shared_info,
            id: connection.uuid,
            gaps: Vec::new(),
            segments: Vec::new(),
            got_handshake_done: false,
            files: None,
        })
    }

    fn handshake_done(&mut self, connection: &mut Connection<Self>) {
        info!(
            "writing data for new connection: {} ({})",
            connection.forward_flow, connection.uuid
        );
        if !self.got_handshake_done {
            self.got_handshake_done = true;
        }
        log_error!(
            self.shared_info
                .record_conn_info(connection.uuid, &connection.forward_flow),
            "failed to write connection info"
        );

        self.shared_info.capture_errors(|| {
            let id = connection.uuid;
            let base_dir = &self.shared_info.inner.base_dir;
            trace!("creating files for connection {id}");
            let forward_data = File::create(base_dir.join(format!("{id}.f.data")))
                .wrap_err("creating forward data file")?;
            let forward_segments = File::create(base_dir.join(format!("{id}.f.jsonl")))
                .wrap_err("creating forward segments file")?;
            let reverse_data = File::create(base_dir.join(format!("{id}.r.data")))
                .wrap_err("creating reverse data file")?;
            let reverse_segments = File::create(base_dir.join(format!("{id}.r.jsonl")))
                .wrap_err("creating reverse segments file")?;
            self.files = Some(DirectoryOutputHandlerFiles {
                forward_data,
                forward_segments,
                reverse_data,
                reverse_segments,
            });
            Ok(())
        });
    }

    fn data_received(&mut self, connection: &mut Connection<Self>, direction: Direction) {
        let stream = connection.get_stream(direction);
        let readable_len = stream.readable_buffered_length();
        if readable_len > BUFFER_READABLE_THRESHOLD
            || stream.segments_info.len() > BUFFER_SEGMENTS_THRESHOLD
        {
            log_error!(
                self.write_stream_data(connection, direction, Some(readable_len)),
                "failed to write stream data"
            );
        } else if stream.total_buffered_length() > BUFFER_TOTAL_THRESHOLD {
            log_error!(
                self.write_stream_data(connection, direction, Some(BUFFER_TOTAL_THRESHOLD_ADVANCE)),
                "failed to write stream data"
            );
        }
    }

    fn will_retire(&mut self, connection: &mut Connection<Self>) {
        info!(
            "removing connection: {} ({})",
            connection.forward_flow, connection.uuid
        );
        if !self.got_handshake_done {
            // nothing to write if no data
            return;
        }
        log_error!(
            self.write_stream_data(connection, Direction::Forward, None),
            "failed to write final forward stream data"
        );
        log_error!(
            self.write_stream_data(connection, Direction::Reverse, None),
            "failed to write final reverse stream data"
        );
    }
}
