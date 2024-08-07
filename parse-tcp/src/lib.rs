use std::fmt::Debug;
use std::net::IpAddr;

use connection::{Connection, Direction};
use serialized::PacketExtra;

pub mod connection;
pub mod emit;
pub mod flow_table;
pub mod handler;
pub mod parser;
pub mod serialized;
pub mod stream;

/// TCP packet metadata
#[derive(Clone, Debug)]
pub struct TcpMeta {
    /// source address
    pub src_addr: IpAddr,
    /// source port
    pub src_port: u16,
    /// destination address
    pub dst_addr: IpAddr,
    /// destination port
    pub dst_port: u16,
    /// sequence number
    pub seq_number: u32,
    /// acknowledgment number
    pub ack_number: u32,
    /// packet flags
    pub flags: TcpFlags,
    /// raw window value
    pub window: u16,

    // options
    /// window scale option
    pub option_window_scale: Option<u8>,
    /// timestamp option (value, echo)
    pub option_timestamp: Option<(u32, u32)>,
}

/// TCP packet flags (at least, the ones we care about)
#[derive(Clone, Default)]
pub struct TcpFlags {
    /// SYN flag
    pub syn: bool,
    /// ACK flag
    pub ack: bool,
    /// FIN flag
    pub fin: bool,
    /// RST flag
    pub rst: bool,
}

impl Debug for TcpFlags {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[")?;
        let mut has_prev = false;
        macro_rules! write_flag {
            ($flag:expr) => {
                if has_prev {
                    write!(f, ", ")?;
                } else {
                    has_prev = true;
                }
                write!(f, $flag)?;
            };
        }
        if self.syn {
            write_flag!("SYN");
        }
        if self.ack {
            write_flag!("ACK");
        }
        if self.fin {
            write_flag!("FIN");
        }
        if self.rst {
            write_flag!("RST");
        }
        // silence warning
        let _ = has_prev;
        write!(f, "]")?;
        Ok(())
    }
}

/// event handler for connection object
pub trait ConnectionHandler
where
    Self: Sized,
{
    /// initial data provided to new
    type InitialData;
    /// error type raised from new
    type ConstructError;
    /// construct handler object
    fn new(
        init_data: Self::InitialData,
        connection: &mut Connection<Self>,
    ) -> Result<Self, Self::ConstructError>;
    /// called on handshake finish (or incomplete handshake)
    fn handshake_done(&mut self, _connection: &mut Connection<Self>) {}
    /// called on data received
    fn data_received(&mut self, _connection: &mut Connection<Self>, _direction: Direction) {}
    /// called when data is acked, direction is of the ack packet, not the stream
    fn ack_received(&mut self, _connection: &mut Connection<Self>, _direction: Direction) {}
    /// called on FIN
    fn fin_received(&mut self, _connection: &mut Connection<Self>, _direction: Direction) {}
    /// called on RST
    fn rst_received(
        &mut self,
        _connection: &mut Connection<Self>,
        _direction: Direction,
        _extra: PacketExtra,
    ) {
    }
    /// ACK for FIN received for stream
    fn stream_end(&mut self, _connection: &mut Connection<Self>, _direction: Direction) {}
    /// connection fatally desynchronized, `direction` is our best guess for the
    /// direction of the packet which caused the desync
    fn connection_desync(&mut self, _connection: &mut Connection<Self>, _direction: Direction) {}
    /// called when the connection is removed from the hashtable
    fn will_retire(&mut self, _connection: &mut Connection<Self>) {}
}

pub fn setup_log_handlers() {
    use tracing_error::ErrorLayer;
    use tracing_subscriber::prelude::*;
    use tracing_subscriber::{fmt, EnvFilter};

    color_eyre::install().unwrap();

    let fmt_layer = fmt::layer();
    let filter_layer = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new("info"))
        .unwrap();

    tracing_subscriber::registry()
        .with(filter_layer)
        .with(fmt_layer)
        .with(ErrorLayer::default())
        .init();
}

pub fn initialize_logging() {
    use parking_lot::Once;

    static INITIALIZE: Once = Once::new();
    INITIALIZE.call_once(setup_log_handlers);
}
