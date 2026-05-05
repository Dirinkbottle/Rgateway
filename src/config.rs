use std::time::Duration;

/// 网关配置，从 .env 文件和环境变量读取
#[derive(Clone)]
pub struct Config {
    /// Go 后端地址
    pub backend_url: String,
    /// 公开端口（对外服务）
    pub public_port: u16,
    /// 管理端口（内部使用）
    pub admin_port: u16,
    /// 默认缓存 TTL
    pub default_ttl: Duration,
    /// 最大缓存条目数
    pub max_entries: u64,
}

const THREE_DAYS: u64 = 259200;

impl Config {
    pub fn from_env() -> Self {
        // 加载 .env 文件（失败不报错，比如生产环境没有 .env 用系统环境变量）
        let _ = dotenvy::dotenv();

        Self {
            backend_url: std::env::var("BACKEND_URL")
                .unwrap_or_else(|_| "http://127.0.0.1:8080".into()),
            public_port: parse_env("PUBLIC_PORT", 3000),
            admin_port: parse_env("ADMIN_PORT", 3001),
            default_ttl: Duration::from_secs(parse_env("CACHE_TTL_SECS", THREE_DAYS)),
            max_entries: parse_env("CACHE_MAX_ENTRIES", 10000),
        }
    }
}

fn parse_env<T: std::str::FromStr>(key: &str, default: T) -> T {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}
