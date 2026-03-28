//! Crawling engine and indicator extraction for kagami.
//!
//! Provides a BFS web crawler with SOCKS5 proxy support (for Tor .onion
//! access) and regex-based indicator extraction.

pub mod bfs;
pub mod extractor;

pub use bfs::BfsCrawler;
pub use extractor::{IndicatorExtractor, LinkExtractor};
