//! 严格 CORS 校验
//!
//! - Preflight OPTIONS：校验 Origin，返回 CORS 头，不转发到后端
//! - 实际请求：校验 Origin，添加 CORS 响应头
//! - 不匹配：不添加任何 CORS 头（浏览器自动拒绝）

use std::collections::HashSet;

use super::config::CorsConfig;

/// CORS 守卫
pub struct CorsGuard {
    /// 允许的来源（HashSet，O(1) 查找）
    allowed_origins: HashSet<String>,
    /// 允许的方法（逗号分隔）
    allowed_methods: String,
    /// 允许的 Header（逗号分隔）
    allowed_headers: String,
    /// 预检缓存时间（秒）
    max_age: String,
    /// 是否允许携带凭证
    allow_credentials: bool,
}

impl CorsGuard {
    pub fn new(config: &CorsConfig) -> Self {
        Self {
            allowed_origins: config.allowed_origins.iter().cloned().collect(),
            allowed_methods: config.allowed_methods.join(", "),
            allowed_headers: config.allowed_headers.join(", "),
            max_age: config.max_age.to_string(),
            allow_credentials: config.allow_credentials,
        }
    }

    /// 检查 origin 是否在允许列表中
    ///
    /// 支持精确匹配和 localhost/0.0.0.0 开发域名匹配（任意端口）
    fn is_origin_allowed(&self, origin: &str) -> bool {
        if self.allowed_origins.contains(origin) {
            return true;
        }
        
        // 开发域名：允许 localhost 和 0.0.0.0 的任意端口
        if let Some(rest) = origin.strip_prefix("http://").or_else(|| origin.strip_prefix("https://")) {
            let host = rest.split(':').next().unwrap_or(rest);
            if host == "localhost" || host == "0.0.0.0" || host == "127.0.0.1" {
                return true;
            }
        }
        false
    }

    /// 处理 CORS 预检请求（OPTIONS）
    ///
    /// 返回 None 表示 Origin 不在白名单，浏览器将自动拒绝
    /// 返回 Some((status, headers)) 表示通过
    pub fn handle_preflight(
        &self,
        origin: &str,
    ) -> Option<(axum::http::StatusCode, Vec<(String, String)>)> {
        tracing::info!("CORS preflight: origin={}", origin);
        if !self.is_origin_allowed(origin) {
            tracing::warn!("CORS rejected: origin={}", origin);
            return None;
        }

        let mut headers = vec![
            (
                "Access-Control-Allow-Origin".to_string(),
                origin.to_string(),
            ),
            (
                "Access-Control-Allow-Methods".to_string(),
                self.allowed_methods.clone(),
            ),
            (
                "Access-Control-Allow-Headers".to_string(),
                self.allowed_headers.clone(),
            ),
            (
                "Access-Control-Max-Age".to_string(),
                self.max_age.clone(),
            ),
        ];

        if self.allow_credentials {
            headers.push((
                "Access-Control-Allow-Credentials".to_string(),
                "true".to_string(),
            ));
        }

        Some((axum::http::StatusCode::NO_CONTENT, headers))
    }

    /// 为实际请求添加 CORS 响应头
    ///
    /// Origin 不在白名单时返回空 Vec（不添加任何 CORS 头）
    pub fn add_cors_headers(&self, origin: &str) -> Vec<(String, String)> {
        tracing::info!("CORS actual: origin={}", origin);
        if !self.is_origin_allowed(origin) {
            tracing::warn!("CORS rejected: origin={}", origin);
            return vec![];
        }

        let mut headers = vec![(
            "Access-Control-Allow-Origin".to_string(),
            origin.to_string(),
        )];

        if self.allow_credentials {
            headers.push((
                "Access-Control-Allow-Credentials".to_string(),
                "true".to_string(),
            ));
        }

        headers
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::watchdog::config::CorsConfig;

    fn make_guard(creds: bool) -> CorsGuard {
        CorsGuard::new(&CorsConfig {
            allowed_origins: vec![
                "http://localhost:8080".to_string(),
                "https://example.com".to_string(),
            ],
            allowed_methods: vec!["GET".to_string(), "POST".to_string()],
            allowed_headers: vec!["Content-Type".to_string()],
            max_age: 3600,
            allow_credentials: creds,
        })
    }

    #[test]
    fn test_allowed_origin_accepted() {
        let g = make_guard(false);
        assert!(g.is_origin_allowed("http://localhost:8080"));
        assert!(g.is_origin_allowed("https://example.com"));
    }

    #[test]
    fn test_disallowed_origin_rejected() {
        let g = make_guard(false);
        assert!(!g.is_origin_allowed("http://evil.com"));
        assert!(!g.is_origin_allowed("https://attacker.net"));
    }

    #[test]
    fn test_localhost_any_port_allowed() {
        let g = make_guard(false);
        assert!(g.is_origin_allowed("http://localhost:9999"));
        assert!(g.is_origin_allowed("http://localhost:3000"));
        assert!(g.is_origin_allowed("http://127.0.0.1:8080"));
        assert!(g.is_origin_allowed("http://0.0.0.0:3000"));
    }

    #[test]
    fn test_preflight_returns_methods() {
        let g = make_guard(false);
        let result = g.handle_preflight("http://localhost:8080");
        assert!(result.is_some());
        let (_, headers) = result.unwrap();
        let methods = headers.iter().find(|(k, _)| k == "Access-Control-Allow-Methods");
        assert!(methods.is_some());
    }

    #[test]
    fn test_credentials_header_when_enabled() {
        let g = make_guard(true);
        let headers = g.add_cors_headers("http://localhost:8080");
        let creds = headers.iter().find(|(k, _)| k == "Access-Control-Allow-Credentials");
        assert!(creds.is_some());
        assert_eq!(creds.unwrap().1, "true");
    }

    #[test]
    fn test_disallowed_origin_returns_empty() {
        let g = make_guard(false);
        let headers = g.add_cors_headers("http://evil.com");
        assert!(headers.is_empty());
    }

    #[test]
    fn test_preflight_rejected_for_unknown_origin() {
        let g = make_guard(false);
        let result = g.handle_preflight("http://evil.com");
        assert!(result.is_none());
    }
}
