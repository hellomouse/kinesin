use std::fmt::Debug;
use std::net::IpAddr;

pub mod connection;
pub mod flow_table;
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
#[derive(Clone)]
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
        let mut list = f.debug_list();
        if self.syn {
            list.entry(&"SYN");
        }
        if self.ack {
            list.entry(&"ACK");
        }
        if self.fin {
            list.entry(&"FIN");
        }
        if self.rst {
            list.entry(&"RST");
        }
        Ok(())
    }
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
