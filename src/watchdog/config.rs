//! Watchdog JSON 配置定义
//!
//! 所有安全规则集中在一个 JSON 文件中，便于 Web 管理页面读取和修改。
//! 字段全部 #[derive(Serialize)] 以支持序列化回 JSON。

use std::collections::HashMap;
use std::path::Path;

/// 顶层 Watchdog 配置
#[derive(serde::Deserialize, Clone, serde::Serialize)]
pub struct WatchdogConfig {
    pub version: u32,
    pub cors: CorsConfig,
    pub crypto: CryptoConfig,
    pub rate_limit: RateLimitConfig,
    pub network: NetworkConfig,
    pub rules: Vec<Rule>,
    /// 是否拒绝未在规则中声明的 body 字段
    #[serde(default)]
    pub reject_unknown_fields: bool,
    /// 是否拒绝未在规则中声明的 query 参数
    #[serde(default)]
    pub reject_unknown_query: bool,
}

/// 网络配置
#[derive(serde::Deserialize, Clone, serde::Serialize)]
pub struct NetworkConfig {
    /// CIDR 表示的可信代理 IP 列表（如 ["127.0.0.1/32", "10.0.0.0/8"]）
    pub trusted_proxies: Vec<String>,
    /// 是否启用 Cookie 挑战
    #[serde(default)]
    pub cookie_challenge_enabled: bool,
}

/// 加密相关配置
#[derive(serde::Deserialize, Clone, serde::Serialize)]
pub struct CryptoConfig {
    /// 滚动码最大允许跳跃（容忍网络乱序）
    pub max_nonce_jump: u64,
    /// 会话超时（秒），超时后重置滚动码
    pub session_timeout_secs: u64,
    /// 挑战握手有效期（秒）
    #[serde(default = "default_challenge_timeout")]
    pub challenge_timeout_secs: u64,
    /// 同会话最小请求间隔（毫秒）
    #[serde(default = "default_min_interval")]
    pub min_request_interval_ms: u64,
    /// Bootstrap Token 有效期（秒）
    #[serde(default = "default_bootstrap_ttl")]
    pub bootstrap_token_ttl_secs: u64,
    /// Bootstrap 接口每分钟每 IP 限流
    #[serde(default = "default_bootstrap_rate_limit")]
    pub bootstrap_rate_limit_per_min: u32,
}

fn default_bootstrap_ttl() -> u64 {
    60
}

fn default_bootstrap_rate_limit() -> u32 {
    5
}

fn default_challenge_timeout() -> u64 {
    60
}

fn default_min_interval() -> u64 {
    10
}

/// CORS 配置
#[derive(serde::Deserialize, Clone, serde::Serialize)]
pub struct CorsConfig {
    pub allowed_origins: Vec<String>,
    pub allowed_methods: Vec<String>,
    pub allowed_headers: Vec<String>,
    pub max_age: u32,
    pub allow_credentials: bool,
    /// 是否允许 localhost/127.0.0.1/0.0.0.0 任意端口（仅限开发环境）
    #[serde(default)]
    pub dev_localhost_bypass: bool,
}

/// IP 频率限制配置
#[derive(serde::Deserialize, Clone, serde::Serialize)]
pub struct RateLimitConfig {
    /// 默认每秒请求数
    pub default_rps: u32,
    /// 触发封禁的阈值（超过此值直接封禁）
    pub ban_threshold: u32,
    /// 封禁持续时间（秒）
    pub ban_duration_secs: u64,
    /// 白名单 IP
    pub whitelist: Vec<String>,
}

/// API 端点规则
#[derive(serde::Deserialize, Clone, serde::Serialize)]
pub struct Rule {
    /// 规则唯一标识
    pub id: String,
    /// 匹配路径（支持 * 通配符，如 /api/*）
    pub path: String,
    /// 允许的 HTTP 方法
    pub methods: Vec<String>,
    /// 参数校验规则
    pub params: ParamsConfig,
    /// 可选：覆盖全局频率限制
    pub rate_limit: Option<RuleRateLimit>,
}

/// 规则级频率限制覆盖
#[derive(serde::Deserialize, Clone, serde::Serialize)]
pub struct RuleRateLimit {
    pub rps: u32,
}

/// 参数校验配置
#[derive(serde::Deserialize, Clone, serde::Serialize)]
pub struct ParamsConfig {
    pub query: Option<HashMap<String, FieldRule>>,
    pub headers: Option<HashMap<String, FieldRule>>,
    pub body: Option<HashMap<String, FieldRule>>,
}

/// 单个字段的校验规则
#[derive(serde::Deserialize, Clone, serde::Serialize)]
pub struct FieldRule {
    /// 字段类型："string" | "number"
    #[serde(rename = "type")]
    pub field_type: Option<String>,
    /// 是否必填
    pub required: Option<bool>,
    /// 最大长度（字节）
    pub max_len: Option<usize>,
    /// 允许的值列表（白名单）
    pub values: Option<Vec<String>>,
}

#[allow(dead_code)]
impl WatchdogConfig {
    /// 从 JSON 文件加载配置
    pub fn load<P: AsRef<Path>>(path: P) -> Self {
        let content = std::fs::read_to_string(path.as_ref())
            .unwrap_or_else(|e| panic!("无法读取 Watchdog 配置文件 {:?}: {}", path.as_ref(), e));
        Self::from_json_str(&content)
    }

    /// 从 JSON 字符串解析（供 Web API 热更新用）
    pub fn from_json_str(s: &str) -> Self {
        serde_json::from_str(s).expect("Watchdog JSON 配置解析失败")
    }

    /// 序列化回 JSON 字符串（供 Web API 返回当前配置）
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).expect("Watchdog 配置序列化失败")
    }
}
