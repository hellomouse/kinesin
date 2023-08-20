use parse_tcp::initialize_logging;

#[tokio::main]
async fn main() -> eyre::Result<()> {
    initialize_logging();
    Ok(())
}
