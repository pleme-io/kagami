//! Core types and traits for the kagami threat intelligence platform.
//!
//! Provides the foundational abstractions for crawling dark web sites,
//! extracting threat indicators, monitoring credential leaks, and
//! exporting intelligence in standard formats (STIX 2.1, JSON).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

/// Errors that can occur during kagami operations.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A crawl operation failed.
    #[error("crawl error: {0}")]
    Crawl(String),

    /// An indicator extraction failed.
    #[error("extraction error: {0}")]
    Extraction(String),

    /// A leak monitoring operation failed.
    #[error("leak monitor error: {0}")]
    LeakMonitor(String),

    /// An export operation failed.
    #[error("export error: {0}")]
    Export(String),

    /// An HTTP request failed.
    #[error("http error: {0}")]
    Http(String),

    /// A serialization/deserialization error.
    #[error("serde error: {0}")]
    Serde(#[from] serde_json::Error),

    /// An I/O error.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// Convenience alias for `Result<T, Error>`.
pub type Result<T> = std::result::Result<T, Error>;

// ---------------------------------------------------------------------------
// Data types
// ---------------------------------------------------------------------------

/// A target to crawl.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrawlTarget {
    /// The starting URL.
    pub url: String,
    /// Maximum link-follow depth.
    pub depth: u32,
    /// Maximum number of pages to retrieve.
    pub max_pages: u32,
}

/// The result of a crawl operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrawlResult {
    /// The original target specification.
    pub target: CrawlTarget,
    /// Pages successfully crawled.
    pub pages: Vec<CrawledPage>,
    /// When the crawl started.
    pub started_at: DateTime<Utc>,
    /// When the crawl finished.
    pub finished_at: DateTime<Utc>,
    /// An error message if the crawl terminated abnormally.
    pub error: Option<String>,
}

/// A single page retrieved during a crawl.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrawledPage {
    /// The page URL.
    pub url: String,
    /// The page title, if present.
    pub title: Option<String>,
    /// SHA-256 hash of the page body.
    pub content_hash: String,
    /// Links discovered on this page.
    pub links: Vec<String>,
    /// HTTP status code.
    pub status_code: u16,
    /// When this page was crawled.
    pub crawled_at: DateTime<Utc>,
}

/// Classification of a threat indicator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IndicatorType {
    /// An IP address (v4 or v6).
    IpAddress,
    /// A domain name.
    Domain,
    /// A full URL.
    Url,
    /// An email address.
    Email,
    /// A file hash (MD5, SHA-1, SHA-256).
    Hash,
    /// A leaked credential pair.
    Credential,
    /// A Bitcoin address.
    BitcoinAddress,
    /// A Tor hidden service address.
    OnionAddress,
}

/// A single threat indicator extracted from crawled content.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIndicator {
    /// Unique identifier.
    pub id: Uuid,
    /// The type of indicator.
    pub indicator_type: IndicatorType,
    /// The indicator value (IP, domain, hash, etc.).
    pub value: String,
    /// Confidence score (0.0 to 1.0).
    pub confidence: f64,
    /// Where this indicator was found.
    pub source: String,
    /// When this indicator was first observed.
    pub first_seen: DateTime<Utc>,
    /// When this indicator was most recently observed.
    pub last_seen: DateTime<Utc>,
    /// Freeform tags for categorisation.
    pub tags: Vec<String>,
}

/// A credential leak record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeakedCredential {
    /// The domain the credential belongs to.
    pub domain: String,
    /// An email pattern (e.g. `*@example.com`), if known.
    pub email_pattern: Option<String>,
    /// The hash algorithm used (e.g. `bcrypt`, `sha256`), if known.
    pub hash_type: Option<String>,
    /// Where the leak was discovered.
    pub source: String,
    /// When the leak was discovered.
    pub discovered_at: DateTime<Utc>,
}

// ---------------------------------------------------------------------------
// Traits
// ---------------------------------------------------------------------------

/// A web crawler that retrieves pages from a starting URL.
#[async_trait::async_trait]
pub trait Crawler: Send + Sync {
    /// Crawl starting from `target`, returning the collected pages.
    async fn crawl(&mut self, target: &CrawlTarget) -> Result<CrawlResult>;
}

/// Extracts threat indicators from raw page content.
#[async_trait::async_trait]
pub trait ThreatFeedProvider: Send + Sync {
    /// Extract indicators from the given `content`.
    async fn extract(&self, content: &str) -> Result<Vec<ThreatIndicator>>;
}

/// Monitors for credential leaks on specified domains.
#[async_trait::async_trait]
pub trait LeakMonitor: Send + Sync {
    /// Check the given `domains` for leaked credentials.
    async fn check(&self, domains: &[String]) -> Result<Vec<LeakedCredential>>;
}

/// Exports threat indicators to standard formats.
#[async_trait::async_trait]
pub trait IntelExporter: Send + Sync {
    /// Export indicators as a STIX 2.1 JSON bundle.
    async fn export_stix(&self, indicators: &[ThreatIndicator]) -> Result<String>;

    /// Export indicators as a simple JSON array.
    async fn export_json(&self, indicators: &[ThreatIndicator]) -> Result<String>;
}
