//! SeaORM persistence layer for kagami threat intelligence data.
//!
//! Feature-gated behind `persistence`. Provides SQLite-backed stores for
//! crawl results and threat indicators.

use sea_orm::entity::prelude::*;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, Database, DatabaseConnection, EntityTrait, QueryFilter, Set,
};

use kagami_core::{CrawledPage, ThreatIndicator};

// ---------------------------------------------------------------------------
// Entity: crawl_results
// ---------------------------------------------------------------------------

/// SeaORM entity for persisted crawl results.
pub mod crawl_result {
    use sea_orm::entity::prelude::*;

    #[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
    #[sea_orm(table_name = "crawl_results")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = true)]
        pub id: i64,
        pub url: String,
        pub title: Option<String>,
        pub content_hash: String,
        pub status_code: i32,
        pub crawled_at: String,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

// ---------------------------------------------------------------------------
// Entity: threat_indicators
// ---------------------------------------------------------------------------

/// SeaORM entity for persisted threat indicators.
pub mod threat_indicator {
    use sea_orm::entity::prelude::*;

    #[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
    #[sea_orm(table_name = "threat_indicators")]
    pub struct Model {
        #[sea_orm(primary_key)]
        pub id: String,
        pub indicator_type: String,
        pub value: String,
        pub confidence: f64,
        pub source: String,
        pub first_seen: String,
        pub last_seen: String,
        pub tags: String,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

// ---------------------------------------------------------------------------
// SqliteCrawlStore
// ---------------------------------------------------------------------------

/// SQLite-backed store for crawl results.
pub struct SqliteCrawlStore {
    db: DatabaseConnection,
}

impl SqliteCrawlStore {
    /// Connect to the given SQLite database URL.
    ///
    /// Use `"sqlite::memory:"` for an ephemeral in-memory database.
    pub async fn new(db_url: &str) -> Result<Self, DbErr> {
        let db = Database::connect(db_url).await?;
        Ok(Self { db })
    }

    /// Create the `crawl_results` table if it does not exist.
    pub async fn init_tables(&self) -> Result<(), DbErr> {
        let sql = r"
            CREATE TABLE IF NOT EXISTS crawl_results (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                url         TEXT    NOT NULL,
                title       TEXT,
                content_hash TEXT   NOT NULL,
                status_code INTEGER NOT NULL,
                crawled_at  TEXT    NOT NULL
            )
        ";
        self.db
            .execute(sea_orm::Statement::from_string(
                sea_orm::DatabaseBackend::Sqlite,
                sql,
            ))
            .await?;
        Ok(())
    }

    /// Persist a [`CrawledPage`].
    pub async fn save_crawl(&self, page: &CrawledPage) -> Result<(), DbErr> {
        let model = crawl_result::ActiveModel {
            id: sea_orm::ActiveValue::NotSet,
            url: Set(page.url.clone()),
            title: Set(page.title.clone()),
            content_hash: Set(page.content_hash.clone()),
            status_code: Set(i32::from(page.status_code)),
            crawled_at: Set(page.crawled_at.to_rfc3339()),
        };
        model.insert(&self.db).await?;
        Ok(())
    }

    /// Query crawl results whose URL exactly matches `url`.
    pub async fn query_by_url(&self, url: &str) -> Result<Vec<crawl_result::Model>, DbErr> {
        crawl_result::Entity::find()
            .filter(crawl_result::Column::Url.eq(url))
            .all(&self.db)
            .await
    }

    /// Return the total number of stored crawl results.
    pub async fn count(&self) -> Result<u64, DbErr> {
        crawl_result::Entity::find().count(&self.db).await
    }
}

// ---------------------------------------------------------------------------
// SqliteIndicatorStore
// ---------------------------------------------------------------------------

/// SQLite-backed store for threat indicators.
pub struct SqliteIndicatorStore {
    db: DatabaseConnection,
}

impl SqliteIndicatorStore {
    /// Connect to the given SQLite database URL.
    pub async fn new(db_url: &str) -> Result<Self, DbErr> {
        let db = Database::connect(db_url).await?;
        Ok(Self { db })
    }

    /// Create the `threat_indicators` table if it does not exist.
    pub async fn init_tables(&self) -> Result<(), DbErr> {
        let sql = r"
            CREATE TABLE IF NOT EXISTS threat_indicators (
                id              TEXT PRIMARY KEY,
                indicator_type  TEXT    NOT NULL,
                value           TEXT    NOT NULL,
                confidence      REAL    NOT NULL,
                source          TEXT    NOT NULL,
                first_seen      TEXT    NOT NULL,
                last_seen       TEXT    NOT NULL,
                tags            TEXT    NOT NULL
            )
        ";
        self.db
            .execute(sea_orm::Statement::from_string(
                sea_orm::DatabaseBackend::Sqlite,
                sql,
            ))
            .await?;
        Ok(())
    }

    /// Persist a [`ThreatIndicator`].
    pub async fn save_indicator(&self, indicator: &ThreatIndicator) -> Result<(), DbErr> {
        let model = threat_indicator::ActiveModel {
            id: Set(indicator.id.to_string()),
            indicator_type: Set(format!("{:?}", indicator.indicator_type)),
            value: Set(indicator.value.clone()),
            confidence: Set(indicator.confidence),
            source: Set(indicator.source.clone()),
            first_seen: Set(indicator.first_seen.to_rfc3339()),
            last_seen: Set(indicator.last_seen.to_rfc3339()),
            tags: Set(serde_json::to_string(&indicator.tags).unwrap_or_default()),
        };
        threat_indicator::Entity::insert(model)
            .exec_without_returning(&self.db)
            .await?;
        Ok(())
    }

    /// Query indicators by type (e.g. `"IpAddress"`, `"Email"`).
    pub async fn query_by_type(
        &self,
        indicator_type: &str,
    ) -> Result<Vec<threat_indicator::Model>, DbErr> {
        threat_indicator::Entity::find()
            .filter(threat_indicator::Column::IndicatorType.eq(indicator_type))
            .all(&self.db)
            .await
    }

    /// Find a single indicator by its exact value.
    pub async fn find_by_value(
        &self,
        value: &str,
    ) -> Result<Option<threat_indicator::Model>, DbErr> {
        threat_indicator::Entity::find()
            .filter(threat_indicator::Column::Value.eq(value))
            .one(&self.db)
            .await
    }

    /// Return the total number of stored indicators.
    pub async fn count(&self) -> Result<u64, DbErr> {
        threat_indicator::Entity::find().count(&self.db).await
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use kagami_core::IndicatorType;
    use uuid::Uuid;

    use super::*;

    fn sample_page() -> CrawledPage {
        CrawledPage {
            url: "http://example.onion/page1".into(),
            title: Some("Test Page".into()),
            content_hash: "abc123".into(),
            links: vec!["http://example.onion/page2".into()],
            status_code: 200,
            crawled_at: Utc::now(),
        }
    }

    fn sample_indicator(indicator_type: IndicatorType, value: &str) -> ThreatIndicator {
        let now = Utc::now();
        ThreatIndicator {
            id: Uuid::new_v4(),
            indicator_type,
            value: value.into(),
            confidence: 0.85,
            source: "test".into(),
            first_seen: now,
            last_seen: now,
            tags: vec!["test-tag".into()],
        }
    }

    #[tokio::test]
    async fn store_crawl_result() {
        let store = SqliteCrawlStore::new("sqlite::memory:").await.unwrap();
        store.init_tables().await.unwrap();

        let page = sample_page();
        store.save_crawl(&page).await.unwrap();

        let count = store.count().await.unwrap();
        assert_eq!(count, 1);
    }

    #[tokio::test]
    async fn query_crawl_by_url() {
        let store = SqliteCrawlStore::new("sqlite::memory:").await.unwrap();
        store.init_tables().await.unwrap();

        let page = sample_page();
        store.save_crawl(&page).await.unwrap();

        let results = store.query_by_url("http://example.onion/page1").await.unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].url, "http://example.onion/page1");
        assert_eq!(results[0].title.as_deref(), Some("Test Page"));
        assert_eq!(results[0].status_code, 200);

        let empty = store.query_by_url("http://nonexistent.onion").await.unwrap();
        assert!(empty.is_empty());
    }

    #[tokio::test]
    async fn store_indicator() {
        let store = SqliteIndicatorStore::new("sqlite::memory:").await.unwrap();
        store.init_tables().await.unwrap();

        let indicator = sample_indicator(IndicatorType::IpAddress, "192.168.1.1");
        store.save_indicator(&indicator).await.unwrap();

        let count = store.count().await.unwrap();
        assert_eq!(count, 1);

        let results = store.query_by_type("IpAddress").await.unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].value, "192.168.1.1");
        assert!((results[0].confidence - 0.85).abs() < f64::EPSILON);
    }

    #[tokio::test]
    async fn dedup_indicator() {
        let store = SqliteIndicatorStore::new("sqlite::memory:").await.unwrap();
        store.init_tables().await.unwrap();

        let indicator = sample_indicator(IndicatorType::Email, "bad@evil.com");
        store.save_indicator(&indicator).await.unwrap();

        // Inserting the same ID again should fail (primary key conflict).
        let result = store.save_indicator(&indicator).await;
        assert!(result.is_err());

        // Only the original row should exist.
        let count = store.count().await.unwrap();
        assert_eq!(count, 1);
    }

    #[tokio::test]
    async fn find_indicator_by_value() {
        let store = SqliteIndicatorStore::new("sqlite::memory:").await.unwrap();
        store.init_tables().await.unwrap();

        let ip = sample_indicator(IndicatorType::IpAddress, "10.0.0.1");
        let email = sample_indicator(IndicatorType::Email, "user@example.com");
        store.save_indicator(&ip).await.unwrap();
        store.save_indicator(&email).await.unwrap();

        let found = store.find_by_value("10.0.0.1").await.unwrap();
        assert!(found.is_some());
        assert_eq!(found.unwrap().indicator_type, "IpAddress");

        let not_found = store.find_by_value("nonexistent").await.unwrap();
        assert!(not_found.is_none());
    }
}
