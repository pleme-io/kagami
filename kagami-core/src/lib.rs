//! Core types and traits for the kagami threat intelligence platform.
//!
//! Provides the foundational abstractions for crawling dark web sites,
//! extracting threat indicators, monitoring credential leaks, and
//! exporting intelligence in standard formats (STIX 2.1, JSON).

use std::fmt;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

/// Errors that can occur during kagami operations.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
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
    Serde(String),

    /// An I/O error.
    #[error("io error: {0}")]
    Io(String),
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Self::Serde(e.to_string())
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e.to_string())
    }
}

impl Error {
    /// Whether this error is potentially retryable.
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        matches!(self, Self::Crawl(_) | Self::Http(_) | Self::Io(_))
    }
}

/// Convenience alias for `Result<T, Error>`.
pub type Result<T> = std::result::Result<T, Error>;

// ---------------------------------------------------------------------------
// Data types
// ---------------------------------------------------------------------------

/// A target to crawl.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrawlTarget {
    /// The starting URL.
    pub url: String,
    /// Maximum link-follow depth.
    pub depth: u32,
    /// Maximum number of pages to retrieve.
    pub max_pages: u32,
}

/// The result of a crawl operation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// A single page retrieved during a crawl.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrawledPage {
    /// The page URL.
    pub url: String,
    /// The page title, if present.
    #[serde(skip_serializing_if = "Option::is_none")]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
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

impl fmt::Display for IndicatorType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IpAddress => write!(f, "IpAddress"),
            Self::Domain => write!(f, "Domain"),
            Self::Url => write!(f, "Url"),
            Self::Email => write!(f, "Email"),
            Self::Hash => write!(f, "Hash"),
            Self::Credential => write!(f, "Credential"),
            Self::BitcoinAddress => write!(f, "BitcoinAddress"),
            Self::OnionAddress => write!(f, "OnionAddress"),
        }
    }
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
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LeakedCredential {
    /// The domain the credential belongs to.
    pub domain: String,
    /// An email pattern (e.g. `*@example.com`), if known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email_pattern: Option<String>,
    /// The hash algorithm used (e.g. `bcrypt`, `sha256`), if known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash_type: Option<String>,
    /// Where the leak was discovered.
    pub source: String,
    /// When the leak was discovered.
    pub discovered_at: DateTime<Utc>,
}

// ---------------------------------------------------------------------------
// STIX 2.1 object types
// ---------------------------------------------------------------------------

/// STIX 2.1 SDO (Structured Data Object) types.
///
/// Covers the core object types from the STIX 2.1 specification used
/// in threat intelligence exchange.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum StixObjectType {
    /// An observable pattern with context (IOC).
    Indicator,
    /// Observed cyber-relevant data.
    ObservedData,
    /// A directional link between two STIX objects.
    Relationship,
    /// A report that an indicator was seen.
    Sighting,
    /// An individual or group with malicious intent.
    ThreatActor,
    /// Malicious software.
    Malware,
    /// A security weakness (CVE, etc.).
    Vulnerability,
    /// Physical or virtual resources used by threat actors.
    Infrastructure,
    /// A coordinated set of malicious activities.
    Campaign,
    /// A TTP (tactic, technique, procedure).
    AttackPattern,
}

impl fmt::Display for StixObjectType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Indicator => write!(f, "indicator"),
            Self::ObservedData => write!(f, "observed-data"),
            Self::Relationship => write!(f, "relationship"),
            Self::Sighting => write!(f, "sighting"),
            Self::ThreatActor => write!(f, "threat-actor"),
            Self::Malware => write!(f, "malware"),
            Self::Vulnerability => write!(f, "vulnerability"),
            Self::Infrastructure => write!(f, "infrastructure"),
            Self::Campaign => write!(f, "campaign"),
            Self::AttackPattern => write!(f, "attack-pattern"),
        }
    }
}

// ---------------------------------------------------------------------------
// TLP markings
// ---------------------------------------------------------------------------

/// Traffic Light Protocol (TLP) marking for data classification.
///
/// Based on FIRST TLP v2.0 standard used in STIX 2.1 marking definitions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum TlpMarking {
    /// For public disclosure; no restrictions.
    #[default]
    Clear,
    /// Community-wide sharing; not for public disclosure.
    Green,
    /// Limited sharing within the organization and clients.
    Amber,
    /// Restricted to the organization only (stricter Amber).
    AmberStrict,
    /// For named recipients only; no further sharing.
    Red,
}

impl TlpMarking {
    /// Whether data with this marking can be shared beyond the original recipient.
    ///
    /// Returns `true` for `Clear`, `Green`, and `Amber`. Returns `false`
    /// for `AmberStrict` and `Red`.
    #[must_use]
    pub fn can_share(&self) -> bool {
        matches!(self, Self::Clear | Self::Green | Self::Amber)
    }
}

impl fmt::Display for TlpMarking {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Clear => write!(f, "TLP:CLEAR"),
            Self::Green => write!(f, "TLP:GREEN"),
            Self::Amber => write!(f, "TLP:AMBER"),
            Self::AmberStrict => write!(f, "TLP:AMBER+STRICT"),
            Self::Red => write!(f, "TLP:RED"),
        }
    }
}

// ---------------------------------------------------------------------------
// Crawl state machine
// ---------------------------------------------------------------------------

/// State machine for a crawl operation.
///
/// Modelled after the Ahmia crawler pipeline: pages transition through
/// connection, fetching, parsing, and indexing stages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum CrawlState {
    /// Queued, not yet started.
    #[default]
    Pending,
    /// Establishing connection to the target.
    Connecting,
    /// Downloading page content.
    Fetching,
    /// Extracting data from downloaded content.
    Parsing,
    /// Writing extracted data to the index/store.
    Indexing,
    /// Successfully finished.
    Complete,
    /// Terminated with an error.
    Failed,
    /// Paused due to rate limiting.
    RateLimited,
}

impl CrawlState {
    /// Whether this state is terminal (no further transitions expected).
    #[must_use]
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Complete | Self::Failed)
    }
}

impl fmt::Display for CrawlState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pending => write!(f, "Pending"),
            Self::Connecting => write!(f, "Connecting"),
            Self::Fetching => write!(f, "Fetching"),
            Self::Parsing => write!(f, "Parsing"),
            Self::Indexing => write!(f, "Indexing"),
            Self::Complete => write!(f, "Complete"),
            Self::Failed => write!(f, "Failed"),
            Self::RateLimited => write!(f, "RateLimited"),
        }
    }
}

// ---------------------------------------------------------------------------
// Confidence scoring
// ---------------------------------------------------------------------------

/// A confidence score on a 0-100 scale (STIX 2.1 confidence).
///
/// Maps to the STIX 2.1 confidence scale where 0-29 is "low",
/// 30-69 is "medium", and 70-100 is "high".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Confidence(u8);

impl Confidence {
    /// Create a new confidence value. Returns `None` if `value > 100`.
    #[must_use]
    pub fn new(value: u8) -> Option<Self> {
        if value <= 100 {
            Some(Self(value))
        } else {
            None
        }
    }

    /// Return the raw numeric value.
    #[must_use]
    pub fn value(&self) -> u8 {
        self.0
    }

    /// Return a human-readable label: `"low"`, `"medium"`, or `"high"`.
    #[must_use]
    pub fn label(&self) -> &'static str {
        match self.0 {
            0..=29 => "low",
            30..=69 => "medium",
            _ => "high",
        }
    }
}

impl fmt::Display for Confidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.0, self.label())
    }
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn indicator_type_display() {
        assert_eq!(IndicatorType::IpAddress.to_string(), "IpAddress");
        assert_eq!(IndicatorType::Domain.to_string(), "Domain");
        assert_eq!(IndicatorType::Url.to_string(), "Url");
        assert_eq!(IndicatorType::Email.to_string(), "Email");
        assert_eq!(IndicatorType::Hash.to_string(), "Hash");
        assert_eq!(IndicatorType::Credential.to_string(), "Credential");
        assert_eq!(IndicatorType::BitcoinAddress.to_string(), "BitcoinAddress");
        assert_eq!(IndicatorType::OnionAddress.to_string(), "OnionAddress");
    }

    #[test]
    fn error_is_retryable() {
        assert!(Error::Crawl("test".into()).is_retryable());
        assert!(Error::Http("test".into()).is_retryable());
        assert!(Error::Io("test".into()).is_retryable());
        assert!(!Error::Export("test".into()).is_retryable());
        assert!(!Error::Serde("test".into()).is_retryable());
        assert!(!Error::LeakMonitor("test".into()).is_retryable());
    }

    #[test]
    fn error_partial_eq() {
        assert_eq!(Error::Crawl("a".into()), Error::Crawl("a".into()));
        assert_ne!(Error::Crawl("a".into()), Error::Http("a".into()));
    }

    #[test]
    fn crawl_target_serde_roundtrip() {
        let target = CrawlTarget {
            url: "http://example.onion".into(),
            depth: 3,
            max_pages: 50,
        };
        let json = serde_json::to_string(&target).unwrap();
        let back: CrawlTarget = serde_json::from_str(&json).unwrap();
        assert_eq!(target, back);
    }

    #[test]
    fn leaked_credential_serde_roundtrip() {
        let cred = LeakedCredential {
            domain: "example.com".into(),
            email_pattern: Some("*@example.com".into()),
            hash_type: None,
            source: "breach-db".into(),
            discovered_at: Utc::now(),
        };
        let json = serde_json::to_string(&cred).unwrap();
        let back: LeakedCredential = serde_json::from_str(&json).unwrap();
        assert_eq!(cred, back);
    }

    #[test]
    fn leaked_credential_skip_none_fields() {
        let cred = LeakedCredential {
            domain: "example.com".into(),
            email_pattern: None,
            hash_type: None,
            source: "test".into(),
            discovered_at: Utc::now(),
        };
        let json = serde_json::to_string(&cred).unwrap();
        assert!(!json.contains("email_pattern"));
        assert!(!json.contains("hash_type"));
    }

    #[test]
    fn crawled_page_serde_roundtrip() {
        let page = CrawledPage {
            url: "http://example.com".into(),
            title: Some("Test".into()),
            content_hash: "abc123".into(),
            links: vec!["http://other.com".into()],
            status_code: 200,
            crawled_at: Utc::now(),
        };
        let json = serde_json::to_string(&page).unwrap();
        let back: CrawledPage = serde_json::from_str(&json).unwrap();
        assert_eq!(page, back);
    }

    // -----------------------------------------------------------------------
    // StixObjectType tests
    // -----------------------------------------------------------------------

    #[test]
    fn stix_object_type_display() {
        assert_eq!(StixObjectType::Indicator.to_string(), "indicator");
        assert_eq!(StixObjectType::ObservedData.to_string(), "observed-data");
        assert_eq!(StixObjectType::Relationship.to_string(), "relationship");
        assert_eq!(StixObjectType::Sighting.to_string(), "sighting");
        assert_eq!(StixObjectType::ThreatActor.to_string(), "threat-actor");
        assert_eq!(StixObjectType::Malware.to_string(), "malware");
        assert_eq!(StixObjectType::Vulnerability.to_string(), "vulnerability");
        assert_eq!(StixObjectType::Infrastructure.to_string(), "infrastructure");
        assert_eq!(StixObjectType::Campaign.to_string(), "campaign");
        assert_eq!(StixObjectType::AttackPattern.to_string(), "attack-pattern");
    }

    #[test]
    fn stix_object_type_serde_roundtrip() {
        let types = [
            StixObjectType::Indicator,
            StixObjectType::ObservedData,
            StixObjectType::Relationship,
            StixObjectType::Sighting,
            StixObjectType::ThreatActor,
            StixObjectType::Malware,
            StixObjectType::Vulnerability,
            StixObjectType::Infrastructure,
            StixObjectType::Campaign,
            StixObjectType::AttackPattern,
        ];
        for t in types {
            let json = serde_json::to_string(&t).unwrap();
            let back: StixObjectType = serde_json::from_str(&json).unwrap();
            assert_eq!(t, back);
        }
    }

    #[test]
    fn stix_object_type_hash_in_set() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(StixObjectType::Indicator);
        set.insert(StixObjectType::Malware);
        set.insert(StixObjectType::Indicator); // duplicate
        assert_eq!(set.len(), 2);
    }

    // -----------------------------------------------------------------------
    // TlpMarking tests
    // -----------------------------------------------------------------------

    #[test]
    fn tlp_marking_default_is_clear() {
        assert_eq!(TlpMarking::default(), TlpMarking::Clear);
    }

    #[test]
    fn tlp_marking_display() {
        assert_eq!(TlpMarking::Clear.to_string(), "TLP:CLEAR");
        assert_eq!(TlpMarking::Green.to_string(), "TLP:GREEN");
        assert_eq!(TlpMarking::Amber.to_string(), "TLP:AMBER");
        assert_eq!(TlpMarking::AmberStrict.to_string(), "TLP:AMBER+STRICT");
        assert_eq!(TlpMarking::Red.to_string(), "TLP:RED");
    }

    #[test]
    fn tlp_marking_can_share() {
        assert!(TlpMarking::Clear.can_share());
        assert!(TlpMarking::Green.can_share());
        assert!(TlpMarking::Amber.can_share());
        assert!(!TlpMarking::AmberStrict.can_share());
        assert!(!TlpMarking::Red.can_share());
    }

    #[test]
    fn tlp_marking_serde_roundtrip() {
        let markings = [
            TlpMarking::Clear,
            TlpMarking::Green,
            TlpMarking::Amber,
            TlpMarking::AmberStrict,
            TlpMarking::Red,
        ];
        for m in markings {
            let json = serde_json::to_string(&m).unwrap();
            let back: TlpMarking = serde_json::from_str(&json).unwrap();
            assert_eq!(m, back);
        }
    }

    // -----------------------------------------------------------------------
    // CrawlState tests
    // -----------------------------------------------------------------------

    #[test]
    fn crawl_state_default_is_pending() {
        assert_eq!(CrawlState::default(), CrawlState::Pending);
    }

    #[test]
    fn crawl_state_is_terminal() {
        assert!(!CrawlState::Pending.is_terminal());
        assert!(!CrawlState::Connecting.is_terminal());
        assert!(!CrawlState::Fetching.is_terminal());
        assert!(!CrawlState::Parsing.is_terminal());
        assert!(!CrawlState::Indexing.is_terminal());
        assert!(CrawlState::Complete.is_terminal());
        assert!(CrawlState::Failed.is_terminal());
        assert!(!CrawlState::RateLimited.is_terminal());
    }

    #[test]
    fn crawl_state_display() {
        assert_eq!(CrawlState::Pending.to_string(), "Pending");
        assert_eq!(CrawlState::Connecting.to_string(), "Connecting");
        assert_eq!(CrawlState::Fetching.to_string(), "Fetching");
        assert_eq!(CrawlState::Parsing.to_string(), "Parsing");
        assert_eq!(CrawlState::Indexing.to_string(), "Indexing");
        assert_eq!(CrawlState::Complete.to_string(), "Complete");
        assert_eq!(CrawlState::Failed.to_string(), "Failed");
        assert_eq!(CrawlState::RateLimited.to_string(), "RateLimited");
    }

    #[test]
    fn crawl_state_serde_roundtrip() {
        let states = [
            CrawlState::Pending,
            CrawlState::Connecting,
            CrawlState::Fetching,
            CrawlState::Parsing,
            CrawlState::Indexing,
            CrawlState::Complete,
            CrawlState::Failed,
            CrawlState::RateLimited,
        ];
        for s in states {
            let json = serde_json::to_string(&s).unwrap();
            let back: CrawlState = serde_json::from_str(&json).unwrap();
            assert_eq!(s, back);
        }
    }

    // -----------------------------------------------------------------------
    // Confidence tests
    // -----------------------------------------------------------------------

    #[test]
    fn confidence_new_valid() {
        assert!(Confidence::new(0).is_some());
        assert!(Confidence::new(50).is_some());
        assert!(Confidence::new(100).is_some());
    }

    #[test]
    fn confidence_new_invalid() {
        assert!(Confidence::new(101).is_none());
        assert!(Confidence::new(255).is_none());
    }

    #[test]
    fn confidence_value() {
        let c = Confidence::new(42).unwrap();
        assert_eq!(c.value(), 42);
    }

    #[test]
    fn confidence_labels() {
        assert_eq!(Confidence::new(0).unwrap().label(), "low");
        assert_eq!(Confidence::new(29).unwrap().label(), "low");
        assert_eq!(Confidence::new(30).unwrap().label(), "medium");
        assert_eq!(Confidence::new(69).unwrap().label(), "medium");
        assert_eq!(Confidence::new(70).unwrap().label(), "high");
        assert_eq!(Confidence::new(100).unwrap().label(), "high");
    }

    #[test]
    fn confidence_display() {
        let c = Confidence::new(85).unwrap();
        assert_eq!(c.to_string(), "85 (high)");

        let c = Confidence::new(10).unwrap();
        assert_eq!(c.to_string(), "10 (low)");

        let c = Confidence::new(50).unwrap();
        assert_eq!(c.to_string(), "50 (medium)");
    }

    #[test]
    fn confidence_serde_roundtrip() {
        let c = Confidence::new(75).unwrap();
        let json = serde_json::to_string(&c).unwrap();
        let back: Confidence = serde_json::from_str(&json).unwrap();
        assert_eq!(c, back);
    }

    #[test]
    fn confidence_equality() {
        let a = Confidence::new(50).unwrap();
        let b = Confidence::new(50).unwrap();
        let c = Confidence::new(51).unwrap();
        assert_eq!(a, b);
        assert_ne!(a, c);
    }
}
