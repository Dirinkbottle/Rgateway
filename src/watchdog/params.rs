//! 参数校验层
//!
//! 根据 watchdog.json 中定义的规则，校验请求的：
//! - HTTP 方法是否允许
//! - Query 参数类型、必填、长度
//! - Header 值白名单
//! - Body JSON 字段类型、必填、长度
//!
//! 任一校验失败立即返回 400，利用 Rust 类型系统在入口处拒绝非法请求。

use axum::http::{HeaderMap, Method};
use std::collections::HashMap;

use super::config::FieldRule;
use super::matcher::RuleBuckets;

/// 参数校验结果
pub enum ParamCheckResult {
    /// 校验通过
    Ok,
    /// 无匹配规则（白名单模式，未注册的端点直接拒绝）
    NoRule,
    /// HTTP 方法不允许
    MethodNotAllowed,
    /// 参数校验失败（附带中文错误信息）
    InvalidParam(String),
}

/// 参数校验器
pub struct ParamValidator {
    buckets: RuleBuckets,
    reject_unknown_fields: bool,
    reject_unknown_query: bool,
}

impl ParamValidator {
    pub fn new(
        buckets: RuleBuckets,
        reject_unknown_fields: bool,
        reject_unknown_query: bool,
    ) -> Self {
        Self {
            buckets,
            reject_unknown_fields,
            reject_unknown_query,
        }
    }

    /// 校验请求参数
    pub fn validate(
        &self,
        method: &Method,
        path: &str,
        query: &str,
        headers: &HeaderMap,
        body: &[u8],
    ) -> ParamCheckResult {
        // 1. 查找匹配规则（先按 method+path，再按 path only）
        let rule = match self.buckets.find_rule(method.as_str(), path) {
            Some(r) => r,
            None => {
                // 路径存在但 method 不匹配 → MethodNotAllowed
                // 路径不存在 → NoRule
                return if self.buckets.find_rule_by_path(path).is_some() {
                    ParamCheckResult::MethodNotAllowed
                } else {
                    ParamCheckResult::NoRule
                };
            }
        };

        // 2. 方法校验（双重检查，find_rule 已过滤 method）
        if !rule
            .methods
            .iter()
            .any(|m| m.eq_ignore_ascii_case(method.as_str()))
        {
            return ParamCheckResult::MethodNotAllowed;
        }

        // 3. 路径合法性
        if path.contains("..") || path.contains('\0') || path.len() > 2048 {
            return ParamCheckResult::InvalidParam("路径不合法".to_string());
        }

        // 4. Query 参数校验
        if let Some(ref query_rules) = rule.params.query {
            let query_params = parse_query(query);
            for (key, field_rule) in query_rules {
                match query_params.get(key.as_str()) {
                    Some(val) => {
                        if let Err(e) = validate_field_value(val, field_rule) {
                            return ParamCheckResult::InvalidParam(format!(
                                "Query 参数 '{}' 校验失败: {}",
                                key, e
                            ));
                        }
                    }
                    None if field_rule.required.unwrap_or(false) => {
                        return ParamCheckResult::InvalidParam(format!(
                            "缺少必需的 Query 参数: '{}'",
                            key
                        ));
                    }
                    _ => {}
                }
            }
            // 拒绝未声明的 query 参数
            if self.reject_unknown_query {
                for qkey in query_params.keys() {
                    if !query_rules.contains_key(*qkey) {
                        return ParamCheckResult::InvalidParam(format!(
                            "未声明的 Query 参数: '{}'",
                            qkey
                        ));
                    }
                }
            }
        }

        // 5. Header 校验
        if let Some(ref header_rules) = rule.params.headers {
            for (key, field_rule) in header_rules {
                let val = headers.get(key.as_str()).and_then(|v| v.to_str().ok());
                match val {
                    Some(v) => {
                        if let Some(ref allowed) = field_rule.values
                            && !allowed.iter().any(|a| a.eq_ignore_ascii_case(v))
                        {
                            return ParamCheckResult::InvalidParam(format!(
                                "Header '{}' 值不允许: '{}'",
                                key, v
                            ));
                        }
                    }
                    None if field_rule.required.unwrap_or(false) => {
                        return ParamCheckResult::InvalidParam(format!(
                            "缺少必需的 Header: '{}'",
                            key
                        ));
                    }
                    _ => {}
                }
            }
        }

        // 6. Body 校验（JSON）
        if let Some(ref body_rules) = rule.params.body {
            // 检查是否有 required 字段
            let has_required = body_rules.values().any(|r| r.required.unwrap_or(false));

            if body.is_empty() {
                // 空 body：如果有 required 字段则拒绝
                if has_required {
                    let missing: Vec<&str> = body_rules
                        .iter()
                        .filter(|(_, r)| r.required.unwrap_or(false))
                        .map(|(k, _)| k.as_str())
                        .collect();
                    return ParamCheckResult::InvalidParam(format!(
                        "缺少必需的 Body 字段: {}",
                        missing.join(", ")
                    ));
                }
                // 空 body 且无 required 字段，跳过 body 校验
            } else {
                // 非空 body 必须是合法 UTF-8 + JSON 对象
                let body_str = match std::str::from_utf8(body) {
                    Ok(s) => s,
                    Err(_) => {
                        return ParamCheckResult::InvalidParam(
                            "Body 不是合法的 UTF-8 编码".to_string(),
                        );
                    }
                };
                let body_json: HashMap<String, serde_json::Value> =
                    match serde_json::from_str(body_str) {
                        Ok(serde_json::Value::Object(map)) => map.into_iter().collect(),
                        Ok(_) => {
                            return ParamCheckResult::InvalidParam(
                                "Body 必须是 JSON 对象".to_string(),
                            );
                        }
                        Err(_) => {
                            return ParamCheckResult::InvalidParam(
                                "Body 不是合法的 JSON".to_string(),
                            );
                        }
                    };
                for (key, field_rule) in body_rules {
                    match body_json.get(key.as_str()) {
                        Some(val) => {
                            let val_str = match val {
                                serde_json::Value::String(s) => s.clone(),
                                other => other.to_string(),
                            };
                            if let Err(e) = validate_field_value(&val_str, field_rule) {
                                return ParamCheckResult::InvalidParam(format!(
                                    "Body 字段 '{}' 校验失败: {}",
                                    key, e
                                ));
                            }
                        }
                        None if field_rule.required.unwrap_or(false) => {
                            return ParamCheckResult::InvalidParam(format!(
                                "缺少必需的 Body 字段: '{}'",
                                key
                            ));
                        }
                        _ => {}
                    }
                }
                // 拒绝未声明的 body 字段
                if self.reject_unknown_fields {
                    for bkey in body_json.keys() {
                        if !body_rules.contains_key(bkey) {
                            return ParamCheckResult::InvalidParam(format!(
                                "未声明的 Body 字段: '{}'",
                                bkey
                            ));
                        }
                    }
                }
            }
        }

        ParamCheckResult::Ok
    }
}

/// 解析 query string 为 HashMap
fn parse_query(query: &str) -> HashMap<&str, &str> {
    query
        .split('&')
        .filter_map(|pair| {
            let mut parts = pair.splitn(2, '=');
            Some((parts.next()?, parts.next().unwrap_or("")))
        })
        .collect()
}

/// 校验单个字段值
fn validate_field_value(value: &str, rule: &FieldRule) -> Result<(), String> {
    // 长度校验
    if let Some(max_len) = rule.max_len
        && value.len() > max_len
    {
        return Err(format!("长度 {} 超过限制 {}", value.len(), max_len));
    }

    // 值白名单校验
    if let Some(ref allowed) = rule.values
        && !allowed.iter().any(|a| a == value)
    {
        return Err(format!("值 '{}' 不在允许列表中", value));
    }

    // 类型校验
    match rule.field_type.as_deref() {
        Some("number") => {
            value
                .parse::<f64>()
                .map_err(|_| "不是有效数字".to_string())?;
        }
        Some("string") | None => {} // 字符串无需额外校验
        _ => {}
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::watchdog::config::{
        CorsConfig, CryptoConfig, FieldRule, NetworkConfig, ParamsConfig, RateLimitConfig, Rule,
        WatchdogConfig,
    };
    use crate::watchdog::matcher::RuleBuckets;
    use axum::http::{HeaderMap, Method};

    fn make_config(rules: Vec<Rule>) -> WatchdogConfig {
        WatchdogConfig {
            version: 1,
            cors: CorsConfig {
                allowed_origins: vec![],
                allowed_methods: vec![],
                allowed_headers: vec![],
                max_age: 3600,
                allow_credentials: false,
                dev_localhost_bypass: false,
            },
            crypto: CryptoConfig {
                max_nonce_jump: 10,
                session_timeout_secs: 300,
                challenge_timeout_secs: 60,
                min_request_interval_ms: 10,
                bootstrap_token_ttl_secs: 60,
                bootstrap_rate_limit_per_min: 5,
            },
            rate_limit: RateLimitConfig {
                default_rps: 50,
                ban_threshold: 100,
                ban_duration_secs: 300,
                whitelist: vec![],
            },
            network: NetworkConfig {
                trusted_proxies: vec![],
                cookie_challenge_enabled: false,
            },
            rules,
            reject_unknown_fields: false,
            reject_unknown_query: false,
        }
    }

    fn sites_rule() -> Rule {
        let mut query = std::collections::HashMap::new();
        query.insert(
            "category".to_string(),
            FieldRule {
                field_type: Some("string".to_string()),
                required: Some(false),
                max_len: Some(50),
                values: None,
            },
        );
        query.insert(
            "page".to_string(),
            FieldRule {
                field_type: Some("number".to_string()),
                required: Some(false),
                max_len: None,
                values: None,
            },
        );
        Rule {
            id: "sites".to_string(),
            path: "/api/sites".to_string(),
            methods: vec!["GET".to_string()],
            params: ParamsConfig {
                query: Some(query),
                headers: None,
                body: None,
            },
            rate_limit: None,
        }
    }

    fn wildcard_api_rule() -> Rule {
        Rule {
            id: "api_wildcard".to_string(),
            path: "/api/*".to_string(),
            methods: vec!["GET".to_string(), "POST".to_string()],
            params: ParamsConfig {
                query: None,
                headers: None,
                body: None,
            },
            rate_limit: None,
        }
    }

    fn validator(rules: Vec<Rule>) -> ParamValidator {
        let config = make_config(rules);
        let buckets = RuleBuckets::build(&config);
        ParamValidator::new(buckets, false, false)
    }

    #[test]
    fn test_valid_params_pass() {
        let v = validator(vec![sites_rule()]);
        let headers = HeaderMap::new();
        let result = v.validate(
            &Method::GET,
            "/api/sites",
            "category=news&page=1",
            &headers,
            &[],
        );
        assert!(matches!(result, ParamCheckResult::Ok));
    }

    #[test]
    fn test_invalid_method_rejected() {
        let v = validator(vec![sites_rule()]);
        let headers = HeaderMap::new();
        let result = v.validate(&Method::POST, "/api/sites", "", &headers, &[]);
        assert!(matches!(result, ParamCheckResult::MethodNotAllowed));
    }

    #[test]
    fn test_unknown_path_rejected() {
        let v = validator(vec![sites_rule()]);
        let headers = HeaderMap::new();
        let result = v.validate(&Method::GET, "/unknown/path", "", &headers, &[]);
        assert!(matches!(result, ParamCheckResult::NoRule));
    }

    #[test]
    fn test_path_traversal_rejected() {
        // 需要通配符规则让路径匹配，才能触发 .. 检查
        let v = validator(vec![sites_rule(), wildcard_api_rule()]);
        let headers = HeaderMap::new();
        let result = v.validate(&Method::GET, "/api/../../../etc/passwd", "", &headers, &[]);
        assert!(matches!(result, ParamCheckResult::InvalidParam(_)));
    }

    #[test]
    fn test_query_max_len_exceeded() {
        let v = validator(vec![sites_rule()]);
        let headers = HeaderMap::new();
        let long_val = "a".repeat(51);
        let query = format!("category={}", long_val);
        let result = v.validate(&Method::GET, "/api/sites", &query, &headers, &[]);
        assert!(matches!(result, ParamCheckResult::InvalidParam(_)));
    }

    #[test]
    fn test_invalid_number_type() {
        let v = validator(vec![sites_rule()]);
        let headers = HeaderMap::new();
        let result = v.validate(&Method::GET, "/api/sites", "page=abc", &headers, &[]);
        assert!(matches!(result, ParamCheckResult::InvalidParam(_)));
    }

    // === Body 校验测试 ===

    fn rule_with_body() -> Rule {
        let mut body = std::collections::HashMap::new();
        body.insert(
            "name".to_string(),
            FieldRule {
                field_type: Some("string".to_string()),
                required: Some(true),
                max_len: Some(100),
                values: None,
            },
        );
        Rule {
            id: "create-item".to_string(),
            path: "/api/items".to_string(),
            methods: vec!["POST".to_string()],
            params: ParamsConfig {
                query: None,
                headers: None,
                body: Some(body),
            },
            rate_limit: None,
        }
    }

    #[test]
    fn test_body_invalid_utf8_rejected() {
        let v = validator(vec![rule_with_body()]);
        let headers = HeaderMap::new();
        // 非法 UTF-8 字节
        let bad_body: &[u8] = &[0xFF, 0xFE, 0x00, 0x01];
        let result = v.validate(&Method::POST, "/api/items", "", &headers, bad_body);
        assert!(matches!(result, ParamCheckResult::InvalidParam(ref msg) if msg.contains("UTF-8")));
    }

    #[test]
    fn test_body_invalid_json_rejected() {
        let v = validator(vec![rule_with_body()]);
        let headers = HeaderMap::new();
        let result = v.validate(&Method::POST, "/api/items", "", &headers, b"not json {{{");
        assert!(matches!(result, ParamCheckResult::InvalidParam(ref msg) if msg.contains("JSON")));
    }

    #[test]
    fn test_body_json_array_rejected() {
        let v = validator(vec![rule_with_body()]);
        let headers = HeaderMap::new();
        let result = v.validate(&Method::POST, "/api/items", "", &headers, b"[1,2,3]");
        assert!(
            matches!(result, ParamCheckResult::InvalidParam(ref msg) if msg.contains("JSON 对象"))
        );
    }

    #[test]
    fn test_body_json_string_rejected() {
        let v = validator(vec![rule_with_body()]);
        let headers = HeaderMap::new();
        let result = v.validate(&Method::POST, "/api/items", "", &headers, b"\"hello\"");
        assert!(
            matches!(result, ParamCheckResult::InvalidParam(ref msg) if msg.contains("JSON 对象"))
        );
    }

    #[test]
    fn test_body_valid_json_passes() {
        let v = validator(vec![rule_with_body()]);
        let headers = HeaderMap::new();
        let result = v.validate(
            &Method::POST,
            "/api/items",
            "",
            &headers,
            br#"{"name":"test"}"#,
        );
        assert!(matches!(result, ParamCheckResult::Ok));
    }

    #[test]
    fn test_body_empty_rejected_when_required_fields_exist() {
        let v = validator(vec![rule_with_body()]);
        let headers = HeaderMap::new();
        // 空 body + 有 required 字段 → 应拒绝
        let result = v.validate(&Method::POST, "/api/items", "", &headers, &[]);
        assert!(matches!(result, ParamCheckResult::InvalidParam(ref msg) if msg.contains("name")));
    }

    #[test]
    fn test_body_required_field_missing_rejected() {
        let v = validator(vec![rule_with_body()]);
        let headers = HeaderMap::new();
        let result = v.validate(
            &Method::POST,
            "/api/items",
            "",
            &headers,
            br#"{"other":"value"}"#,
        );
        assert!(matches!(result, ParamCheckResult::InvalidParam(ref msg) if msg.contains("name")));
    }
}
