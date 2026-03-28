//! Intelligence export and leak monitoring for kagami.
//!
//! Provides STIX 2.1 bundle generation and credential leak pattern matching.
//! With the `persistence` feature, also provides SQLite-backed stores for
//! crawl results and threat indicators.

pub mod leak;
#[cfg(feature = "persistence")]
pub mod persistence;
pub mod stix;

pub use leak::PatternLeakMonitor;
#[cfg(feature = "persistence")]
pub use persistence::{SqliteCrawlStore, SqliteIndicatorStore};
pub use stix::StixExporter;
