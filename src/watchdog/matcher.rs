//! O(1) 哈希桶规则匹配器
//!
//! 启动时一次性构建：
//! - 精确路径 → HashMap（O(1) 查找）
//! - 通配符路径 → Vec（前缀匹配，数量少）
//! - 运行时缓存 → DashMap（相同路径二次命中 O(1)）

use dashmap::DashMap;
use std::collections::HashMap;

use super::config::{Rule, WatchdogConfig};

/// O(1) 规则匹配器
pub struct RuleBuckets {
    /// 精确路径：(method, path) → rules 索引
    exact: HashMap<(String, String), usize>,
    /// 通配符路径：(method, prefix) → rules 索引
    wildcard: Vec<(String, String, usize)>,
    /// 按路径索引（忽略 method），用于 method 不匹配时仍能找到规则
    exact_by_path: HashMap<String, usize>,
    wildcard_by_path: Vec<(String, usize)>,
    /// 完整规则列表
    pub rules: Vec<Rule>,
    /// 运行时缓存：相同 (method, path) 直接命中
    cache: DashMap<(String, String), usize>,
}

impl RuleBuckets {
    /// 从配置构建哈希桶（启动时调用一次）
    pub fn build(config: &WatchdogConfig) -> Self {
        let mut exact = HashMap::new();
        let mut wildcard = Vec::new();
        let mut exact_by_path = HashMap::new();
        let mut wildcard_by_path = Vec::new();

        for (idx, rule) in config.rules.iter().enumerate() {
            for method in &rule.methods {
                if rule.path.contains('*') {
                    let prefix = rule.path.replace('*', "");
                    wildcard.push((method.clone(), prefix.clone(), idx));
                    wildcard_by_path.push((prefix, idx));
                } else {
                    exact.insert((method.clone(), rule.path.clone()), idx);
                    exact_by_path.insert(rule.path.clone(), idx);
                }
            }
        }

        Self {
            exact,
            wildcard,
            exact_by_path,
            wildcard_by_path,
            rules: config.rules.clone(),
            cache: DashMap::new(),
        }
    }

    /// O(1) 查找匹配规则
    ///
    /// 查找顺序：
    /// 1. 运行时缓存（DashMap，O(1)）
    /// 2. 精确路径 HashMap（O(1)）
    /// 3. 通配符前缀 Vec（线性，数量少通常 <10）
    pub fn find_rule(&self, method: &str, path: &str) -> Option<&Rule> {
        let key = (method.to_string(), path.to_string());

        // 1. 查运行时缓存
        if let Some(idx) = self.cache.get(&key) {
            return self.rules.get(*idx);
        }

        // 2. 精确匹配 HashMap (O(1))
        if let Some(&idx) = self.exact.get(&key) {
            self.cache.insert(key, idx);
            return self.rules.get(idx);
        }

        // 3. 通配符前缀匹配
        for (m, prefix, idx) in &self.wildcard {
            if method == m && path.starts_with(prefix) {
                self.cache.insert(key, *idx);
                return self.rules.get(*idx);
            }
        }

        None
    }

    /// 按路径查找规则（忽略 method），用于 method 不匹配时仍能找到规则
    pub fn find_rule_by_path(&self, path: &str) -> Option<&Rule> {
        if let Some(&idx) = self.exact_by_path.get(path) {
            return self.rules.get(idx);
        }
        for (prefix, idx) in &self.wildcard_by_path {
            if path.starts_with(prefix) {
                return self.rules.get(*idx);
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::watchdog::config::{
        CorsConfig, CryptoConfig, NetworkConfig, ParamsConfig, RateLimitConfig, Rule,
        WatchdogConfig,
    };

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

    fn make_rule(id: &str, path: &str, methods: Vec<&str>) -> Rule {
        Rule {
            id: id.to_string(),
            path: path.to_string(),
            methods: methods.iter().map(|s| s.to_string()).collect(),
            params: ParamsConfig {
                query: None,
                headers: None,
                body: None,
            },
            rate_limit: None,
        }
    }

    #[test]
    fn test_exact_match() {
        let config = make_config(vec![make_rule("r1", "/api/sites", vec!["GET"])]);
        let buckets = RuleBuckets::build(&config);
        let rule = buckets.find_rule("GET", "/api/sites");
        assert!(rule.is_some());
        assert_eq!(rule.unwrap().id, "r1");
    }

    #[test]
    fn test_wildcard_match() {
        let config = make_config(vec![make_rule("r2", "/api/*", vec!["GET"])]);
        let buckets = RuleBuckets::build(&config);
        let rule = buckets.find_rule("GET", "/api/users/123");
        assert!(rule.is_some());
        assert_eq!(rule.unwrap().id, "r2");
    }

    #[test]
    fn test_no_match_returns_none() {
        let config = make_config(vec![make_rule("r1", "/api/sites", vec!["GET"])]);
        let buckets = RuleBuckets::build(&config);
        let rule = buckets.find_rule("GET", "/unknown");
        assert!(rule.is_none());
    }

    #[test]
    fn test_method_mismatch() {
        let config = make_config(vec![make_rule("r1", "/api/sites", vec!["GET"])]);
        let buckets = RuleBuckets::build(&config);
        let rule = buckets.find_rule("POST", "/api/sites");
        assert!(rule.is_none());
    }

    #[test]
    fn test_cache_hit() {
        let config = make_config(vec![make_rule("r1", "/api/sites", vec!["GET"])]);
        let buckets = RuleBuckets::build(&config);
        // 第一次查找
        let r1 = buckets.find_rule("GET", "/api/sites");
        assert!(r1.is_some());
        // 第二次查找（应从缓存命中）
        let r2 = buckets.find_rule("GET", "/api/sites");
        assert!(r2.is_some());
        assert_eq!(r1.unwrap().id, r2.unwrap().id);
    }

    #[test]
    fn test_multiple_methods() {
        let config = make_config(vec![make_rule("r1", "/api/sites", vec!["GET", "POST"])]);
        let buckets = RuleBuckets::build(&config);
        assert!(buckets.find_rule("GET", "/api/sites").is_some());
        assert!(buckets.find_rule("POST", "/api/sites").is_some());
        assert!(buckets.find_rule("DELETE", "/api/sites").is_none());
    }
}
