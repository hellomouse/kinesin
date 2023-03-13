use tracing::{trace, debug, info};

fn main() {
    tracing_subscriber::fmt::init();
    trace!("hi");
    debug!("Hello, world!");
    info!("info");
}
