//! Watchdog 安全模块
//!
//! 为 Rgateway 提供多层安全防护：
//! - config: JSON 规则配置加载
//! - matcher: O(1) 哈希桶规则匹配
//! - decrypt: Wasm 加密请求解密 + 滚动码状态机
//! - ja3_filter: TLS 指纹校验（模拟）
//! - inject: SQL 注入 / XSS 检测
//! - params: 参数校验（方法、路径、Header、Body）
//! - rate_limit: IP 频率限制
//! - cors: 严格 CORS 校验

pub mod challenge;
pub mod config;
pub mod cors;
pub mod decrypt;
pub mod inject;
pub mod ja3_filter;
pub mod matcher;
pub mod params;
pub mod rate_limit;
