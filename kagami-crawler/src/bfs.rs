//! BFS web crawler with SOCKS5 proxy support and optional kakuremino anonymous transport.

use std::collections::HashSet;
use std::sync::Arc;

use bytes::Bytes;
use chrono::Utc;
use http_body_util::{BodyExt, Empty};
use hyper::Request;
use hyper_util::rt::TokioIo;
use reqwest::Client;
use sha2::{Digest, Sha256};
use tracing::{debug, info, warn};

use kagami_core::{CrawlResult, CrawlTarget, CrawledPage, Crawler, Error, Result};
use kakuremino::AnonTransport;

use crate::extractor::LinkExtractor;

/// Default SOCKS5 proxy address for Tor.
const DEFAULT_SOCKS_PROXY: &str = "socks5h://127.0.0.1:9050";

/// A breadth-first crawler that follows links up to a configurable depth.
///
/// Supports two modes for `.onion` crawling:
/// - **SOCKS5 proxy** (default): uses `reqwest` with a SOCKS5 proxy URL.
/// - **kakuremino transport**: uses an [`AnonTransport`] implementation (e.g.,
///   [`kakuremino::TorTransport`]) for anonymous connectivity via Arti.
///
/// For clearnet URLs, the crawler always falls back to the `reqwest` client.
pub struct BfsCrawler {
    /// Maximum link-follow depth (0 = seed page only).
    pub max_depth: u32,
    /// Maximum pages to retrieve in a single crawl.
    pub max_pages: u32,
    /// User-Agent header value.
    pub user_agent: String,
    /// Optional SOCKS5 proxy URL (defaults to Tor on 9050).
    pub socks_proxy: Option<String>,
    /// Optional anonymous transport for `.onion` URL crawling.
    transport: Option<Arc<dyn AnonTransport>>,
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
            transport: None,
            visited: HashSet::new(),
        }
    }

    /// Set an anonymous transport for `.onion` URL crawling.
    ///
    /// When set, `.onion` URLs are fetched through the transport instead of
    /// the SOCKS5 proxy. Non-`.onion` URLs continue to use `reqwest`.
    #[must_use]
    pub fn with_transport(mut self, transport: Arc<dyn AnonTransport>) -> Self {
        self.transport = Some(transport);
        self
    }

    /// Create a crawler pre-configured to use kakuremino's `TorTransport`.
    ///
    /// The Tor client is bootstrapped eagerly. This may take 10-30 seconds on
    /// the first call while Tor consensus is downloaded and circuits are built.
    pub async fn with_tor(max_depth: u32, max_pages: u32) -> Result<Self> {
        info!("bootstrapping kakuremino TorTransport for BfsCrawler");
        let transport = kakuremino::TorTransport::bootstrap()
            .await
            .map_err(|e| Error::Http(format!("kakuremino Tor bootstrap failed: {e}")))?;
        let transport: Arc<dyn AnonTransport> = Arc::new(transport);
        Ok(Self::new(max_depth, max_pages).with_transport(transport))
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

    /// Returns `true` if the URL points to a `.onion` hidden service.
    fn is_onion_url(url_str: &str) -> bool {
        url::Url::parse(url_str)
            .ok()
            .and_then(|u| u.host_str().map(|h| h.ends_with(".onion")))
            .unwrap_or(false)
    }

    /// Fetch a `.onion` URL through the kakuremino transport.
    ///
    /// Establishes a raw TCP-like connection via `connect_onion`, then performs
    /// an HTTP/1.1 GET request using `hyper`.
    async fn fetch_via_transport(
        transport: &dyn AnonTransport,
        url_str: &str,
        user_agent: &str,
    ) -> Result<(u16, String)> {
        let parsed =
            url::Url::parse(url_str).map_err(|e| Error::Http(format!("invalid URL: {e}")))?;

        let host = parsed
            .host_str()
            .ok_or_else(|| Error::Http("URL has no host".to_string()))?;
        let port = parsed.port().unwrap_or(80);
        let path = if parsed.path().is_empty() {
            "/"
        } else {
            parsed.path()
        };

        debug!(host, port, path, "connecting via kakuremino transport");
        let stream = transport
            .connect_onion(host, port)
            .await
            .map_err(|e| Error::Http(format!("kakuremino connect_onion failed: {e}")))?;

        let io = TokioIo::new(stream);
        let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
            .await
            .map_err(|e| Error::Http(format!("HTTP handshake failed: {e}")))?;

        // Drive the connection in the background.
        tokio::spawn(async move {
            if let Err(e) = conn.await {
                warn!("HTTP connection error: {e}");
            }
        });

        let req = Request::builder()
            .uri(path)
            .header("Host", host)
            .header("User-Agent", user_agent)
            .body(Empty::<Bytes>::new())
            .map_err(|e| Error::Http(format!("failed to build request: {e}")))?;

        let response = sender
            .send_request(req)
            .await
            .map_err(|e| Error::Http(format!("HTTP request failed: {e}")))?;

        let status = response.status().as_u16();
        let body_bytes = response
            .into_body()
            .collect()
            .await
            .map_err(|e| Error::Http(format!("failed to read response body: {e}")))?
            .to_bytes();

        let body = String::from_utf8_lossy(&body_bytes).into_owned();
        Ok((status, body))
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

            // Choose fetch strategy: kakuremino transport for .onion when
            // available, reqwest for everything else.
            let fetch_result =
                if Self::is_onion_url(&url) && self.transport.is_some() {
                    let transport = self.transport.as_ref().unwrap();
                    Self::fetch_via_transport(transport.as_ref(), &url, &self.user_agent).await
                } else {
                    // Fall back to reqwest (with optional SOCKS5 proxy).
                    match client.get(&url).send().await {
                        Ok(response) => {
                            let status_code = response.status().as_u16();
                            let body = response.text().await.unwrap_or_default();
                            Ok((status_code, body))
                        }
                        Err(e) => Err(Error::Http(e.to_string())),
                    }
                };

            match fetch_result {
                Ok((status_code, body)) => {
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

    #[test]
    fn transport_defaults_to_none() {
        let crawler = BfsCrawler::new(2, 50);
        assert!(crawler.transport.is_none());
    }

    #[test]
    fn detects_onion_urls() {
        assert!(BfsCrawler::is_onion_url(
            "http://duskgytldkxiuqc6.onion/page"
        ));
        assert!(BfsCrawler::is_onion_url(
            "http://exampleonion1234567890abcdef.onion"
        ));
        assert!(!BfsCrawler::is_onion_url("https://example.com"));
        assert!(!BfsCrawler::is_onion_url("not-a-url"));
    }
}
