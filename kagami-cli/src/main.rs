//! CLI for the kagami dark web monitor and threat intelligence platform.

use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

use kagami_core::{CrawlTarget, Crawler, IntelExporter, LeakMonitor, ThreatFeedProvider};
use kagami_crawler::{BfsCrawler, IndicatorExtractor};
use kagami_intel::{PatternLeakMonitor, StixExporter};

/// Kagami — dark web monitor and defensive threat intelligence.
#[derive(Parser)]
#[command(name = "kagami", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Crawl a target URL (optionally through SOCKS5/Tor).
    Crawl {
        /// The starting URL to crawl.
        url: String,

        /// Maximum link-follow depth.
        #[arg(short, long, default_value_t = 2)]
        depth: u32,

        /// Maximum pages to retrieve.
        #[arg(short, long, default_value_t = 50)]
        max_pages: u32,

        /// SOCKS5 proxy URL (default: socks5h://127.0.0.1:9050).
        #[arg(long)]
        proxy: Option<String>,

        /// Disable SOCKS5 proxy (direct connection).
        #[arg(long, default_value_t = false)]
        no_proxy: bool,
    },

    /// Monitor domains for credential leaks.
    Watch {
        /// Domains to monitor.
        #[arg(required = true)]
        domains: Vec<String>,
    },

    /// Export collected indicators to STIX 2.1 or JSON.
    Export {
        /// Output format: "stix" or "json".
        #[arg(short, long, default_value = "stix")]
        format: String,

        /// Input file containing indicators as JSON.
        #[arg(short, long)]
        input: String,

        /// Output file path (stdout if omitted).
        #[arg(short, long)]
        output: Option<String>,
    },

    /// Show crawl and monitoring status.
    Status,
}

#[tokio::main]
async fn main() -> kagami_core::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();

    match cli.command {
        Command::Crawl {
            url,
            depth,
            max_pages,
            proxy,
            no_proxy,
        } => {
            let mut crawler = BfsCrawler::new(depth, max_pages);
            if no_proxy {
                crawler.socks_proxy = None;
            } else if let Some(p) = proxy {
                crawler.socks_proxy = Some(p);
            }

            let target = CrawlTarget {
                url,
                depth,
                max_pages,
            };

            tracing::info!("starting crawl: {:?}", target);
            let result = crawler.crawl(&target).await?;
            tracing::info!("crawled {} pages", result.pages.len());

            // Extract indicators from all crawled pages.
            let extractor = IndicatorExtractor::new();
            let mut all_indicators = Vec::new();
            for page in &result.pages {
                // We use the content hash as a stand-in; in production we'd
                // store the full body.
                let indicators = extractor.extract(&page.url).await?;
                all_indicators.extend(indicators);
            }

            if all_indicators.is_empty() {
                tracing::info!("no threat indicators found");
            } else {
                tracing::info!("found {} indicators", all_indicators.len());
                let json = serde_json::to_string_pretty(&all_indicators)
                    .map_err(kagami_core::Error::Serde)?;
                println!("{json}");
            }
        }

        Command::Watch { domains } => {
            tracing::info!("monitoring {} domains for leaks", domains.len());
            let monitor = PatternLeakMonitor::new();
            let leaks = monitor.check(&domains).await?;
            if leaks.is_empty() {
                tracing::info!("no leaks detected");
            } else {
                tracing::warn!("detected {} leaked credentials", leaks.len());
                let json =
                    serde_json::to_string_pretty(&leaks).map_err(kagami_core::Error::Serde)?;
                println!("{json}");
            }
        }

        Command::Export {
            format,
            input,
            output,
        } => {
            let raw = std::fs::read_to_string(&input).map_err(kagami_core::Error::Io)?;
            let indicators: Vec<kagami_core::ThreatIndicator> =
                serde_json::from_str(&raw).map_err(kagami_core::Error::Serde)?;

            let exporter = StixExporter;
            let exported = match format.as_str() {
                "json" => exporter.export_json(&indicators).await?,
                _ => exporter.export_stix(&indicators).await?,
            };

            if let Some(path) = output {
                std::fs::write(&path, &exported).map_err(kagami_core::Error::Io)?;
                tracing::info!("exported to {path}");
            } else {
                println!("{exported}");
            }
        }

        Command::Status => {
            println!("kagami status: idle (no active crawls or monitors)");
        }
    }

    Ok(())
}
