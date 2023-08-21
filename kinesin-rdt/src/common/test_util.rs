//! Utility functions for testing

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
