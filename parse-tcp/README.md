# parse-tcp

It hopefully parses TCP.

## Usage

```text
2023-08-24T03:40:34.524087Z  INFO reassemble: Hello, world!
Reassemble TCP streams in a packet capture

Usage: reassemble [OPTIONS] --input <INPUT>

Options:
  -f, --input <INPUT>            Input capture file, supports pcap only (not yet pcapng)
  -d, --output-dir <OUTPUT_DIR>  Directory to write stream data. If not provided, will dump to stdout
  -h, --help                     Print help
  -V, --version                  Print version
```

Use environment variable `RUST_LOG` to control logging.
