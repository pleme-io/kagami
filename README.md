# kagami

Dark web threat intelligence platform.

Defensive OSINT tool that crawls `.onion` sites through Tor, extracts threat
indicators (IPs, emails, Bitcoin addresses, hidden services), monitors for
credential leaks, and exports intelligence as STIX 2.1 bundles. Designed for
security teams that need structured dark web monitoring without manual browsing.

## Quick Start

```bash
cargo test                   # run all 48 tests
cargo build --release        # release binary
nix build                    # Nix hermetic build
```

## Crates

| Crate | Purpose |
|-------|---------|
| `kagami-core` | Traits: `Crawler`, `ThreatFeedProvider`, `LeakMonitor`, `IntelExporter` |
| `kagami-crawler` | BFS crawler (reqwest + SOCKS5), link and indicator extraction |
| `kagami-intel` | STIX 2.1 exporter, pattern-based leak monitoring |
| `kagami-cli` | CLI binary with `crawl`, `watch`, `export`, and `status` subcommands |

## Indicator Extraction

Regex-based extraction from crawled pages:

- IPv4 addresses
- Email addresses
- Bitcoin addresses
- `.onion` hidden service URLs

Indicators are converted to STIX 2.1 Indicator SDOs with deterministic IDs
and pattern strings (e.g. `[ipv4-addr:value = '1.2.3.4']`).

## Usage

```bash
# Crawl an .onion site (depth 2, max 50 pages, via local Tor SOCKS5)
kagami crawl http://example.onion --depth 2 --max-pages 50

# Crawl without Tor proxy (clearnet)
kagami crawl http://example.com --no-proxy

# Watch domains for credential leaks
kagami watch example.com target.org

# Export indicators as STIX 2.1
kagami export --input indicators.json --format stix

# Export as plain JSON
kagami export --input indicators.json --format json --output out.json
```

## License

MIT
