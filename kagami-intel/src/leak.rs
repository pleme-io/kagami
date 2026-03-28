//! Credential leak monitoring via pattern matching.

use chrono::Utc;

use kagami_core::{LeakMonitor, LeakedCredential, Result};

/// A leak monitor that checks domains against a set of known leak patterns.
pub struct PatternLeakMonitor {
    /// Known leak patterns: `(domain_pattern, source, hash_type)`.
    patterns: Vec<LeakPattern>,
}

/// A single known leak pattern.
#[derive(Debug, Clone)]
struct LeakPattern {
    /// Domain substring to match against.
    domain_contains: String,
    /// The source/breach name.
    source: String,
    /// Optional hash type.
    hash_type: Option<String>,
}

impl PatternLeakMonitor {
    /// Create a new monitor with no patterns.
    pub fn new() -> Self {
        Self {
            patterns: Vec::new(),
        }
    }

    /// Add a known leak pattern.
    pub fn add_pattern(
        &mut self,
        domain_contains: &str,
        source: &str,
        hash_type: Option<&str>,
    ) {
        self.patterns.push(LeakPattern {
            domain_contains: domain_contains.to_string(),
            source: source.to_string(),
            hash_type: hash_type.map(ToString::to_string),
        });
    }
}

impl Default for PatternLeakMonitor {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl LeakMonitor for PatternLeakMonitor {
    async fn check(&self, domains: &[String]) -> Result<Vec<LeakedCredential>> {
        let now = Utc::now();
        let mut results = Vec::new();

        for domain in domains {
            for pattern in &self.patterns {
                if domain.contains(&pattern.domain_contains) {
                    results.push(LeakedCredential {
                        domain: domain.clone(),
                        email_pattern: Some(format!("*@{domain}")),
                        hash_type: pattern.hash_type.clone(),
                        source: pattern.source.clone(),
                        discovered_at: now,
                    });
                }
            }
        }

        Ok(results)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn empty_patterns_returns_empty() {
        let monitor = PatternLeakMonitor::new();
        let domains = vec!["example.com".to_string()];
        let results = monitor.check(&domains).await.unwrap();
        assert!(results.is_empty());
    }

    #[tokio::test]
    async fn pattern_match_returns_credential() {
        let mut monitor = PatternLeakMonitor::new();
        monitor.add_pattern("example", "breach-db-2024", Some("bcrypt"));

        let domains = vec!["example.com".to_string(), "safe.org".to_string()];
        let results = monitor.check(&domains).await.unwrap();

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].domain, "example.com");
        assert_eq!(results[0].source, "breach-db-2024");
        assert_eq!(results[0].hash_type, Some("bcrypt".to_string()));
    }

    #[tokio::test]
    async fn multiple_patterns_multiple_matches() {
        let mut monitor = PatternLeakMonitor::new();
        monitor.add_pattern("example", "breach-a", None);
        monitor.add_pattern("test", "breach-b", Some("sha256"));

        let domains = vec![
            "example.com".to_string(),
            "test.org".to_string(),
            "safe.net".to_string(),
        ];
        let results = monitor.check(&domains).await.unwrap();

        assert_eq!(results.len(), 2);
    }
}
