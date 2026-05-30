use std::sync::Arc;

use crate::{
    cache::Cache,
    config::Config,
    proxy::Proxy,
    watchdog::{
        challenge::ChallengeManager, config::WatchdogConfig, cors::CorsGuard, decrypt::Decryptor,
        inject::InjectionGuard, ja3_filter::Ja3Filter, params::ParamValidator,
        rate_limit::RateLimiter,
    },
};

pub mod admin;
pub mod gateway;

/// 全局共享状态，注入到 axum Router
#[derive(Clone)]
pub struct AppState {
    pub cache: Arc<Cache>,
    pub proxy: Arc<Proxy>,
    pub config: Arc<Config>,
    /// Watchdog 配置（供 Web API 热更新）
    pub watchdog_config: Arc<WatchdogConfig>,
    /// Wasm 加密请求解密器
    pub decryptor: Arc<Decryptor>,
    /// TLS 指纹过滤器 + Cookie 挑战
    pub ja3_filter: Arc<Ja3Filter>,
    /// SQL 注入 / XSS 检测守卫
    pub inject_guard: Arc<InjectionGuard>,
    /// IP 频率限制器
    pub rate_limiter: Arc<RateLimiter>,
    /// CORS 守卫
    pub cors_guard: Arc<CorsGuard>,
    /// 参数校验器
    pub param_validator: Arc<ParamValidator>,
    /// 挑战-响应管理器
    pub challenge_manager: Arc<ChallengeManager>,
}

impl AppState {
    pub fn new(config: Config) -> Self {
        let proxy = Proxy::new(config.backend_url.clone());
        let cache = Cache::new(config.max_entries);

        // 加载 Watchdog 配置
        let watchdog_config = WatchdogConfig::load(&config.watchdog_config_path);

        // 构建挑战-响应管理器（Bootstrap Token 模式，无需预共享密钥）
        let challenge_manager = ChallengeManager::new(
            watchdog_config.crypto.challenge_timeout_secs,
            watchdog_config.crypto.session_timeout_secs,
            watchdog_config.crypto.min_request_interval_ms,
            watchdog_config.crypto.bootstrap_token_ttl_secs,
            watchdog_config.crypto.bootstrap_rate_limit_per_min,
        );
        let challenge_manager = Arc::new(challenge_manager);

        // 构建安全组件
        let decryptor = Decryptor::new(
            challenge_manager.clone(),
            watchdog_config.crypto.max_nonce_jump,
            watchdog_config.crypto.min_request_interval_ms,
        );
        // Cookie 签名密钥：每次启动生成随机密钥（重启后旧 cookie 失效，可接受）
        let mut cookie_key = [0u8; 32];
        getrandom::getrandom(&mut cookie_key).expect("Cookie 签名密钥生成失败");

        let ja3_filter =
            Ja3Filter::new(cookie_key, watchdog_config.network.cookie_challenge_enabled);
        let inject_guard = InjectionGuard::new();
        let rate_limiter = RateLimiter::new(&watchdog_config.rate_limit);
        let cors_guard = CorsGuard::new(&watchdog_config.cors);

        // 构建规则匹配器 + 参数校验器
        let rule_buckets = crate::watchdog::matcher::RuleBuckets::build(&watchdog_config);
        let param_validator = ParamValidator::new(rule_buckets);

        Self {
            cache: Arc::new(cache),
            proxy: Arc::new(proxy),
            config: Arc::new(config),
            watchdog_config: Arc::new(watchdog_config),
            decryptor: Arc::new(decryptor),
            ja3_filter: Arc::new(ja3_filter),
            inject_guard: Arc::new(inject_guard),
            rate_limiter: Arc::new(rate_limiter),
            cors_guard: Arc::new(cors_guard),
            param_validator: Arc::new(param_validator),
            challenge_manager,
        }
    }
}
