use axum::http::StatusCode;
use moka::future::Cache as MokaCache;
use std::{
    collections::HashMap,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::sync::RwLock;

/// 缓存的 HTTP 响应
#[derive(Clone)]
pub struct CachedResponse {
    pub status: StatusCode,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub expires_at: Instant,
}

/// 缓存统计
#[derive(Clone, Debug, serde::Serialize)]
pub struct CacheStats {
    pub entries: u64,
    pub hits: u64,
    pub misses: u64,
}

/// 网关缓存层：moka 做 LRU + 并发安全，外层管理过期和标签
pub struct Cache {
    store: MokaCache<String, CachedResponse>,
    tag_index: Arc<RwLock<HashMap<String, Vec<String>>>>,
    hits: AtomicU64,
    misses: AtomicU64,
}

impl Cache {
    pub fn new(max_entries: u64) -> Self {
        Self {
            store: MokaCache::new(max_entries),
            tag_index: Arc::new(RwLock::new(HashMap::new())),
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
        }
    }

    /// 查询缓存，过期自动返回 None
    pub async fn get(&self, key: &str) -> Option<CachedResponse> {
        match self.store.get(key).await {
            Some(entry) if entry.expires_at > Instant::now() => {
                self.hits.fetch_add(1, Ordering::Relaxed);
                Some(entry)
            }
            Some(_) => {
                // 过期条目，惰性删除
                self.store.invalidate(key).await;
                self.misses.fetch_add(1, Ordering::Relaxed);
                None
            }
            None => {
                self.misses.fetch_add(1, Ordering::Relaxed);
                None
            }
        }
    }

    /// 写入缓存
    pub async fn set(&self, key: String, resp: CachedResponse, tag: Option<String>) {
        if let Some(ref tag) = tag {
            let mut idx = self.tag_index.write().await;
            idx.entry(tag.clone()).or_default().push(key.clone());
        }
        self.store.insert(key, resp).await;
    }

    /// 按路径精确失效
    pub async fn invalidate_by_path(&self, path: &str) {
        self.store.invalidate(path).await;
    }

    /// 按标签批量失效
    pub async fn invalidate_by_tag(&self, tag: &str) {
        let mut idx = self.tag_index.write().await;
        if let Some(keys) = idx.remove(tag) {
            for key in keys {
                self.store.invalidate(&key).await;
            }
        }
    }

    /// 清空所有缓存
    pub async fn clear(&self) {
        self.store.invalidate_all();
        self.tag_index.write().await.clear();
    }

    /// 缓存统计
    pub fn stats(&self) -> CacheStats {
        CacheStats {
            entries: self.store.entry_count(),
            hits: self.hits.load(Ordering::Relaxed),
            misses: self.misses.load(Ordering::Relaxed),
        }
    }
}

impl CachedResponse {
    /// 从后端响应构造，计算过期时间
    pub fn new(
        status: StatusCode,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
        ttl: Option<Duration>,
        default_ttl: Duration,
    ) -> Self {
        let ttl = ttl.unwrap_or(default_ttl);
        Self {
            status,
            headers,
            body,
            expires_at: Instant::now() + ttl,
        }
    }
}
