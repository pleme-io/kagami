# Kagami — Dark Web Monitor & Threat Intelligence

Defensive OSINT tool for crawling .onion sites, extracting threat indicators,
monitoring credential leaks, and exporting intelligence as STIX 2.1 bundles.

**Tests:** 48

## Architecture

```
kagami-core       — traits (Crawler, ThreatFeedProvider, LeakMonitor, IntelExporter) + types
kagami-crawler    — BFS crawler (reqwest + SOCKS5), link/indicator extraction (regex, scraper)
kagami-intel      — STIX 2.1 exporter, pattern-based leak monitor
kagami-cli        — clap CLI: crawl, watch, export, status — execute() extracted for testability
```

### Key Types

| Type | Kind | Description |
|------|------|-------------|
| `StixObjectType` | Enum | 10 STIX 2.1 types (AttackPattern, Campaign, CourseOfAction, Identity, Indicator, IntrusionSet, Malware, ObservedData, ThreatActor, Vulnerability) |
| `TlpMarking` | Enum | 5 TLP levels (White, Green, Amber, AmberStrict, Red) + can_share() method |
| `CrawlState` | Enum | 8 states (Pending, Fetching, Parsing, Extracted, Indexed, Failed, Skipped, Complete) + is_terminal() method |
| `Confidence` | Newtype | 0-100 confidence score + label() method (returns Low/Medium/High) |
| `Error` | Struct | Clone + PartialEq + is_retryable() |

## Crawling Strategy

BFS from a seed URL. Follows links up to a configurable depth and page limit.
Uses SOCKS5 proxy (default `socks5h://127.0.0.1:9050`) for Tor .onion access.
All HTTP via reqwest with rustls (no native-tls / C FFI).

## Indicator Extraction

Regex-based extraction of:
- IPv4 addresses
- Email addresses
- Bitcoin addresses
- .onion hidden service addresses

## STIX 2.1 Export

Indicators are converted to STIX 2.1 Indicator SDOs inside a Bundle.
Each indicator gets a deterministic `indicator--{uuid}` identifier and a
STIX pattern string (e.g. `[ipv4-addr:value = '1.2.3.4']`).

## Build

```bash
cargo check                  # type-check workspace
cargo test                   # run all tests
cargo build --release -p kagami-cli   # release binary
nix build                    # Nix hermetic build via substrate
```

## CLI

```bash
kagami crawl <URL> --depth 2 --max-pages 50
kagami crawl <URL> --no-proxy          # direct (no Tor)
kagami watch example.com target.org
kagami export --input indicators.json --format stix
kagami export --input indicators.json --format json --output out.json
kagami status
```

## Conventions

- Edition 2024, Rust 1.89.0+, MIT license
- Pure Rust only (rustls, no C FFI)
- shikumi for config, SeaORM for persistence (planned)
- clippy pedantic, release profile: LTO + strip + opt-level z
