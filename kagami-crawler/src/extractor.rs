//! Link and threat indicator extraction from HTML content.

use chrono::Utc;
use regex::Regex;
use uuid::Uuid;

use kagami_core::{IndicatorType, Result, ThreatFeedProvider, ThreatIndicator};

// ---------------------------------------------------------------------------
// Link extraction
// ---------------------------------------------------------------------------

/// Extracts `<a href="...">` links from HTML documents.
pub struct LinkExtractor;

impl LinkExtractor {
    /// Extract all absolute links from `html`, resolving relative links
    /// against `base_url`.
    pub fn extract_links(html: &str, base_url: &str) -> Vec<String> {
        let document = scraper::Html::parse_document(html);
        let selector = scraper::Selector::parse("a[href]").unwrap();
        let base = url::Url::parse(base_url).ok();

        document
            .select(&selector)
            .filter_map(|el| {
                let href = el.value().attr("href")?;
                if let Ok(absolute) = url::Url::parse(href) {
                    Some(absolute.to_string())
                } else if let Some(ref b) = base {
                    b.join(href).ok().map(|u| u.to_string())
                } else {
                    None
                }
            })
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Indicator extraction
// ---------------------------------------------------------------------------

/// Regex-based threat indicator extractor.
///
/// Scans raw text for IP addresses, email addresses, Bitcoin addresses,
/// and `.onion` URLs.
pub struct IndicatorExtractor {
    ip_re: Regex,
    email_re: Regex,
    bitcoin_re: Regex,
    onion_re: Regex,
}

impl Default for IndicatorExtractor {
    fn default() -> Self {
        Self::new()
    }
}

impl IndicatorExtractor {
    /// Create a new extractor with compiled regex patterns.
    pub fn new() -> Self {
        Self {
            ip_re: Regex::new(
                r"\b(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\b",
            )
            .unwrap(),
            email_re: Regex::new(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
                .unwrap(),
            bitcoin_re: Regex::new(r"\b(?:bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}\b").unwrap(),
            onion_re: Regex::new(r"\b[a-z2-7]{16,56}\.onion\b").unwrap(),
        }
    }

    /// Find all matches for a given regex, producing indicators.
    fn find_all(
        &self,
        re: &Regex,
        content: &str,
        indicator_type: IndicatorType,
        source: &str,
    ) -> Vec<ThreatIndicator> {
        let now = Utc::now();
        re.find_iter(content)
            .map(|m| ThreatIndicator {
                id: Uuid::new_v4(),
                indicator_type,
                value: m.as_str().to_string(),
                confidence: 0.5,
                source: source.to_string(),
                first_seen: now,
                last_seen: now,
                tags: Vec::new(),
            })
            .collect()
    }
}

#[async_trait::async_trait]
impl ThreatFeedProvider for IndicatorExtractor {
    async fn extract(&self, content: &str) -> Result<Vec<ThreatIndicator>> {
        let source = "kagami-crawler";
        let mut indicators = Vec::new();

        indicators.extend(self.find_all(&self.ip_re, content, IndicatorType::IpAddress, source));
        indicators.extend(self.find_all(&self.email_re, content, IndicatorType::Email, source));
        indicators.extend(self.find_all(
            &self.bitcoin_re,
            content,
            IndicatorType::BitcoinAddress,
            source,
        ));
        indicators.extend(self.find_all(
            &self.onion_re,
            content,
            IndicatorType::OnionAddress,
            source,
        ));

        Ok(indicators)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_links_from_html() {
        let html = r#"
            <html><body>
                <a href="https://example.com/page1">Page 1</a>
                <a href="/page2">Page 2</a>
                <a href="https://other.com">Other</a>
            </body></html>
        "#;
        let links = LinkExtractor::extract_links(html, "https://example.com");
        assert_eq!(links.len(), 3);
        assert!(links.contains(&"https://example.com/page1".to_string()));
        assert!(links.contains(&"https://example.com/page2".to_string()));
        assert!(links.contains(&"https://other.com/".to_string()));
    }

    #[tokio::test]
    async fn finds_ip_addresses() {
        let extractor = IndicatorExtractor::new();
        let content = "Server at 192.168.1.1 and 10.0.0.255 responded.";
        let indicators = extractor.extract(content).await.unwrap();
        let ips: Vec<&str> = indicators
            .iter()
            .filter(|i| i.indicator_type == IndicatorType::IpAddress)
            .map(|i| i.value.as_str())
            .collect();
        assert_eq!(ips.len(), 2);
        assert!(ips.contains(&"192.168.1.1"));
        assert!(ips.contains(&"10.0.0.255"));
    }

    #[tokio::test]
    async fn finds_email_patterns() {
        let extractor = IndicatorExtractor::new();
        let content = "Contact admin@example.com or support@test.org for details.";
        let indicators = extractor.extract(content).await.unwrap();
        let emails: Vec<&str> = indicators
            .iter()
            .filter(|i| i.indicator_type == IndicatorType::Email)
            .map(|i| i.value.as_str())
            .collect();
        assert_eq!(emails.len(), 2);
        assert!(emails.contains(&"admin@example.com"));
        assert!(emails.contains(&"support@test.org"));
    }

    #[tokio::test]
    async fn finds_onion_urls() {
        let extractor = IndicatorExtractor::new();
        let content = "Visit duskgytldkxiuqc6.onion for the hidden service.";
        let indicators = extractor.extract(content).await.unwrap();
        let onions: Vec<&str> = indicators
            .iter()
            .filter(|i| i.indicator_type == IndicatorType::OnionAddress)
            .map(|i| i.value.as_str())
            .collect();
        assert_eq!(onions.len(), 1);
        assert!(onions.contains(&"duskgytldkxiuqc6.onion"));
    }

    #[tokio::test]
    async fn empty_content_returns_no_indicators() {
        let extractor = IndicatorExtractor::new();
        let indicators = extractor.extract("").await.unwrap();
        assert!(indicators.is_empty());
    }
}
