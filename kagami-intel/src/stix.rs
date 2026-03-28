//! STIX 2.1 bundle export.

use serde_json::{json, Value};
use uuid::Uuid;

use kagami_core::{IndicatorType, IntelExporter, Result, ThreatIndicator};

/// Exports threat indicators as STIX 2.1 JSON bundles.
pub struct StixExporter;

impl StixExporter {
    /// Map an `IndicatorType` to a STIX 2.1 pattern string.
    fn to_stix_pattern(indicator: &ThreatIndicator) -> String {
        match indicator.indicator_type {
            IndicatorType::IpAddress => {
                format!("[ipv4-addr:value = '{}']", indicator.value)
            }
            IndicatorType::Domain => {
                format!("[domain-name:value = '{}']", indicator.value)
            }
            IndicatorType::Url => {
                format!("[url:value = '{}']", indicator.value)
            }
            IndicatorType::Email => {
                format!("[email-addr:value = '{}']", indicator.value)
            }
            IndicatorType::Hash => {
                format!("[file:hashes.'SHA-256' = '{}']", indicator.value)
            }
            IndicatorType::Credential => {
                format!(
                    "[user-account:credential = '{}']",
                    indicator.value
                )
            }
            IndicatorType::BitcoinAddress => {
                format!(
                    "[cryptocurrency-wallet:address = '{}']",
                    indicator.value
                )
            }
            IndicatorType::OnionAddress => {
                format!("[domain-name:value = '{}']", indicator.value)
            }
        }
    }

    /// Convert a single indicator to a STIX 2.1 Indicator SDO.
    fn to_stix_object(indicator: &ThreatIndicator) -> Value {
        json!({
            "type": "indicator",
            "spec_version": "2.1",
            "id": format!("indicator--{}", indicator.id),
            "created": indicator.first_seen.to_rfc3339(),
            "modified": indicator.last_seen.to_rfc3339(),
            "name": format!("{:?}: {}", indicator.indicator_type, indicator.value),
            "pattern": Self::to_stix_pattern(indicator),
            "pattern_type": "stix",
            "valid_from": indicator.first_seen.to_rfc3339(),
            "confidence": (indicator.confidence * 100.0) as u32,
            "labels": indicator.tags,
        })
    }
}

#[async_trait::async_trait]
impl IntelExporter for StixExporter {
    async fn export_stix(&self, indicators: &[ThreatIndicator]) -> Result<String> {
        let objects: Vec<Value> = indicators.iter().map(Self::to_stix_object).collect();

        let bundle = json!({
            "type": "bundle",
            "id": format!("bundle--{}", Uuid::new_v4()),
            "objects": objects,
        });

        serde_json::to_string_pretty(&bundle).map_err(Into::into)
    }

    async fn export_json(&self, indicators: &[ThreatIndicator]) -> Result<String> {
        serde_json::to_string_pretty(indicators).map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use kagami_core::IndicatorType;

    fn sample_indicators() -> Vec<ThreatIndicator> {
        let now = Utc::now();
        vec![
            ThreatIndicator {
                id: Uuid::new_v4(),
                indicator_type: IndicatorType::IpAddress,
                value: "192.168.1.1".to_string(),
                confidence: 0.9,
                source: "test".to_string(),
                first_seen: now,
                last_seen: now,
                tags: vec!["malware".to_string()],
            },
            ThreatIndicator {
                id: Uuid::new_v4(),
                indicator_type: IndicatorType::Email,
                value: "bad@evil.com".to_string(),
                confidence: 0.7,
                source: "test".to_string(),
                first_seen: now,
                last_seen: now,
                tags: vec!["phishing".to_string()],
            },
        ]
    }

    #[tokio::test]
    async fn valid_bundle_structure() {
        let exporter = StixExporter;
        let json_str = exporter.export_stix(&sample_indicators()).await.unwrap();
        let bundle: Value = serde_json::from_str(&json_str).unwrap();

        assert_eq!(bundle["type"], "bundle");
        assert!(bundle["id"].as_str().unwrap().starts_with("bundle--"));
        assert!(bundle["objects"].is_array());
    }

    #[tokio::test]
    async fn indicator_count_matches() {
        let exporter = StixExporter;
        let indicators = sample_indicators();
        let json_str = exporter.export_stix(&indicators).await.unwrap();
        let bundle: Value = serde_json::from_str(&json_str).unwrap();

        assert_eq!(
            bundle["objects"].as_array().unwrap().len(),
            indicators.len()
        );
    }

    #[tokio::test]
    async fn valid_json_output() {
        let exporter = StixExporter;
        let json_str = exporter.export_json(&sample_indicators()).await.unwrap();
        let parsed: Value = serde_json::from_str(&json_str).unwrap();
        assert!(parsed.is_array());
        assert_eq!(parsed.as_array().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn empty_indicators_produce_empty_bundle() {
        let exporter = StixExporter;
        let json_str = exporter.export_stix(&[]).await.unwrap();
        let bundle: Value = serde_json::from_str(&json_str).unwrap();
        assert_eq!(bundle["objects"].as_array().unwrap().len(), 0);
    }
}
