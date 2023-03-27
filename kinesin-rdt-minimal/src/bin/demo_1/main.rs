use tracing::{debug, info, trace};
use krdt_minimal::frame_text::Test;

fn main() {
    tracing_subscriber::fmt::init();
    let _ = Test;
    trace!("hi");
    debug!("Hello, world!");
    info!("info");

    let mut a: Vec<u8> = Vec::with_capacity(32);
    a.resize(32, 0);
    println!("old capacity: {}", a.capacity());
    a.reserve(1);
    println!("new capacity: {}", a.capacity());
}
