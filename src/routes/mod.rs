use std::sync::Arc;

use crate::{cache::Cache, config::Config, proxy::Proxy};

pub mod admin;
pub mod gateway;

/// 全局共享状态，注入到 axum Router
#[derive(Clone)]
pub struct AppState {
    pub cache: Arc<Cache>,
    pub proxy: Arc<Proxy>,
    pub config: Arc<Config>,
}

impl AppState {
    pub fn new(config: Config) -> Self {
        let proxy = Proxy::new(config.backend_url.clone());
        let cache = Cache::new(config.max_entries);
        Self {
            cache: Arc::new(cache),
            proxy: Arc::new(proxy),
            config: Arc::new(config),
        }
    }
}
