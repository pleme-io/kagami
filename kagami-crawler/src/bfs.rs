//! BFS web crawler with SOCKS5 proxy support.

use std::collections::HashSet;

use chrono::Utc;
use reqwest::Client;
use sha2::{Digest, Sha256};
use tracing::{debug, warn};

use kagami_core::{CrawlResult, CrawlTarget, CrawledPage, Crawler, Error, Result};

use crate::extractor::LinkExtractor;

/// Default SOCKS5 proxy address for Tor.
const DEFAULT_SOCKS_PROXY: &str = "socks5h://127.0.0.1:9050";

/// A breadth-first crawler that follows links up to a configurable depth.
pub struct BfsCrawler {
    /// Maximum link-follow depth (0 = seed page only).
    pub max_depth: u32,
    /// Maximum pages to retrieve in a single crawl.
    pub max_pages: u32,
    /// User-Agent header value.
    pub user_agent: String,
    /// Optional SOCKS5 proxy URL (defaults to Tor on 9050).
    pub socks_proxy: Option<String>,
    /// Set of already-visited URLs (persists across calls for dedup).
    visited: HashSet<String>,
}

impl BfsCrawler {
    /// Create a new crawler with the given limits.
    pub fn new(max_depth: u32, max_pages: u32) -> Self {
        Self {
            max_depth,
            max_pages,
            user_agent: String::from("kagami/0.1"),
            socks_proxy: Some(DEFAULT_SOCKS_PROXY.to_string()),
            visited: HashSet::new(),
        }
    }

    /// Build an HTTP client, optionally with SOCKS5 proxy.
    fn build_client(&self) -> Result<Client> {
        let mut builder = Client::builder()
            .user_agent(&self.user_agent)
            .danger_accept_invalid_certs(true);

        if let Some(proxy_url) = &self.socks_proxy {
            let proxy =
                reqwest::Proxy::all(proxy_url).map_err(|e| Error::Http(e.to_string()))?;
            builder = builder.proxy(proxy);
        }

        builder.build().map_err(|e| Error::Http(e.to_string()))
    }

    /// Hash page body with SHA-256.
    fn hash_content(body: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(body.as_bytes());
        format!("{:x}", hasher.finalize())
    }
}

#[async_trait::async_trait]
impl Crawler for BfsCrawler {
    async fn crawl(&mut self, target: &CrawlTarget) -> Result<CrawlResult> {
        let started_at = Utc::now();
        let client = self.build_client()?;

        let effective_max_depth = target.depth.min(self.max_depth);
        let effective_max_pages = target.max_pages.min(self.max_pages);

        let mut pages: Vec<CrawledPage> = Vec::new();
        // Queue entries: (url, depth)
        let mut queue: Vec<(String, u32)> = vec![(target.url.clone(), 0)];
        let mut error: Option<String> = None;

        while let Some((url, depth)) = queue.first().cloned() {
            queue.remove(0);

            if self.visited.contains(&url) {
                continue;
            }

            if pages.len() as u32 >= effective_max_pages {
                break;
            }

            self.visited.insert(url.clone());
            debug!(url = %url, depth, "crawling");

            match client.get(&url).send().await {
                Ok(response) => {
                    let status_code = response.status().as_u16();
                    let body = response
                        .text()
                        .await
                        .unwrap_or_default();

                    let links = LinkExtractor::extract_links(&body, &url);
                    let content_hash = Self::hash_content(&body);

                    // Extract title from HTML.
                    let title = scraper::Html::parse_document(&body)
                        .select(&scraper::Selector::parse("title").unwrap())
                        .next()
                        .map(|el| el.text().collect::<String>());

                    pages.push(CrawledPage {
                        url: url.clone(),
                        title,
                        content_hash,
                        links: links.clone(),
                        status_code,
                        crawled_at: Utc::now(),
                    });

                    // Enqueue discovered links if within depth.
                    if depth < effective_max_depth {
                        for link in links {
                            if !self.visited.contains(&link) {
                                queue.push((link, depth + 1));
                            }
                        }
                    }
                }
                Err(e) => {
                    warn!(url = %url, error = %e, "failed to fetch page");
                    error = Some(e.to_string());
                }
            }
        }

        let finished_at = Utc::now();

        Ok(CrawlResult {
            target: target.clone(),
            pages,
            started_at,
            finished_at,
            error,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn respects_max_depth() {
        let crawler = BfsCrawler::new(2, 100);
        assert_eq!(crawler.max_depth, 2);
    }

    #[test]
    fn respects_max_pages() {
        let crawler = BfsCrawler::new(10, 5);
        assert_eq!(crawler.max_pages, 5);
    }

    #[test]
    fn deduplicates_urls() {
        let mut crawler = BfsCrawler::new(10, 100);
        crawler.visited.insert("https://example.com".to_string());
        assert!(crawler.visited.contains("https://example.com"));
        // Inserting the same URL again should not increase the set size.
        crawler.visited.insert("https://example.com".to_string());
        assert_eq!(crawler.visited.len(), 1);
    }

    #[test]
    fn content_hash_is_deterministic() {
        let hash1 = BfsCrawler::hash_content("hello world");
        let hash2 = BfsCrawler::hash_content("hello world");
        assert_eq!(hash1, hash2);

        let hash3 = BfsCrawler::hash_content("different content");
        assert_ne!(hash1, hash3);
    }
}
