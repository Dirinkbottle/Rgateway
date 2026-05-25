//! TLS 指纹校验（JA3/JA4 模拟）+ Cookie 挑战
//!
//! - User-Agent 自动化工具特征匹配
//! - 浏览器标配 Header 检查（Accept-Language, Accept-Encoding）
//! - Cookie 挑战：首次请求签发签名 Cookie，后续请求必须携带

use std::time::Instant;

use axum::http::HeaderMap;
use dashmap::DashMap;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::net::IpAddr;

type HmacSha256 = Hmac<Sha256>;

/// DashMap 容量上限
const MAX_VALID_COOKIES: usize = 100_000;

/// 已知自动化工具的 User-Agent 特征
const BLOCKED_UA_PATTERNS: &[&str] = &[
    "python-requests",
    "Go-http-client",
    "curl/",
    "wget/",
    "libwww-perl",
    "Scrapy",
    "HttpClient",
    "node-fetch",
    "axios/",
    "insomnia/",
    "python",
    "httpx",
    "aiohttp",
    "postmanruntime",
    "apache-httpclient",
];

/// JA3 校验错误
#[derive(Debug)]
pub enum Ja3Error {
    /// 检测到自动化工具指纹
    SuspiciousFingerprint,
    /// 缺少浏览器标配 Header
    MissingBrowserHeaders,
}

/// JA3/JA4 指纹过滤器 + Cookie 挑战
pub struct Ja3Filter {
    /// Cookie 签名密钥
    cookie_signing_key: [u8; 32],
    /// 有效的 Cookie 令牌
    valid_cookies: DashMap<String, Instant>,
    /// Cookie 最大有效期（秒）
    cookie_max_age: u64,
    /// 是否启用 Cookie 挑战
    cookie_enabled: bool,
}

impl Ja3Filter {
    pub fn new(cookie_signing_key: [u8; 32], cookie_enabled: bool) -> Self {
        Self {
            cookie_signing_key,
            valid_cookies: DashMap::new(),
            cookie_max_age: 86400, // 24 小时
            cookie_enabled,
        }
    }

    /// 校验请求是否来自合法浏览器
    ///
    /// 返回：
    /// - `Ok(None)` — 校验通过，已有有效 Cookie
    /// - `Ok(Some(token))` — 校验通过，需要设置新 Cookie
    /// - `Err(e)` — 校验失败，应拒绝请求
    pub fn check(&self, headers: &HeaderMap, ip: IpAddr) -> Result<Option<String>, Ja3Error> {
        // 1. User-Agent 检查
        let ua = headers
            .get("user-agent")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");

        for pattern in BLOCKED_UA_PATTERNS {
            if ua.to_lowercase().contains(&pattern.to_lowercase()) {
                tracing::warn!(
                    "JA3 过滤：检测到自动化工具 UA='{}', IP={}",
                    ua,
                    ip
                );
                return Err(Ja3Error::SuspiciousFingerprint);
            }
        }

        // 2. 浏览器标配 Header 检查
        if headers.get("accept-language").is_none() {
            tracing::warn!("JA3 过滤：缺少 Accept-Language, IP={}", ip);
            return Err(Ja3Error::MissingBrowserHeaders);
        }

        if headers.get("accept-encoding").is_none() {
            tracing::warn!("JA3 过滤：缺少 Accept-Encoding, IP={}", ip);
            return Err(Ja3Error::MissingBrowserHeaders);
        }

        // 3. Cookie 挑战
        if self.cookie_enabled {
            return self.check_cookie(headers);
        }

        Ok(None)
    }

    /// Cookie 挑战验证
    fn check_cookie(&self, headers: &HeaderMap) -> Result<Option<String>, Ja3Error> {
        if let Some(cookie_header) = headers.get("cookie").and_then(|v| v.to_str().ok()) {
            if let Some(token) = parse_cookie(cookie_header, "zfsg_token") {
                if self.verify_cookie_signature(&token) {
                    return Ok(None); // 有效 Cookie
                }
            }
        }
        // 无有效 Cookie，签发新令牌
        let token = self.issue_cookie();
        Ok(Some(token))
    }

    /// 签发新的 Cookie 令牌
    fn issue_cookie(&self) -> String {
        // 容量检查
        if self.valid_cookies.len() >= MAX_VALID_COOKIES {
            self.cleanup_cookies();
        }

        let mut nonce = [0u8; 8];
        getrandom::getrandom(&mut nonce).expect("随机数生成失败");
        let nonce_hex = hex::encode(nonce);
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let payload = format!("{}:{}", nonce_hex, timestamp);

        let mut mac =
            <HmacSha256 as Mac>::new_from_slice(&self.cookie_signing_key).expect("HMAC 密钥创建失败");
        mac.update(payload.as_bytes());
        let sig = hex::encode(mac.finalize().into_bytes());

        let token = format!("{}.{}", payload, sig);
        self.valid_cookies
            .insert(token.clone(), Instant::now());

        // 清理过期 Cookie
        self.cleanup_cookies();

        token
    }

    /// 验证 Cookie 签名
    fn verify_cookie_signature(&self, token: &str) -> bool {
        // 分割：payload.sig
        let Some(dot_pos) = token.rfind('.') else {
            return false;
        };
        let payload = &token[..dot_pos];
        let sig = &token[dot_pos + 1..];

        // 验证 HMAC 签名
        let mut mac =
            <HmacSha256 as Mac>::new_from_slice(&self.cookie_signing_key).expect("HMAC 密钥创建失败");
        mac.update(payload.as_bytes());
        let expected_sig = hex::encode(mac.finalize().into_bytes());

        use subtle::ConstantTimeEq;
        let eq: bool = sig
            .as_bytes()
            .ct_eq(expected_sig.as_bytes())
            .into();
        if !eq {
            return false;
        }

        // 检查是否在有效集合中
        if let Some(entry) = self.valid_cookies.get(token) {
            entry.elapsed().as_secs() <= self.cookie_max_age
        } else {
            false
        }
    }

    /// 清理过期 Cookie
    fn cleanup_cookies(&self) {
        let max_age = self.cookie_max_age;
        self.valid_cookies
            .retain(|_, v| v.elapsed().as_secs() <= max_age);
    }
}

/// 从 Cookie 头中解析指定名称的值
fn parse_cookie(cookie_header: &str, name: &str) -> Option<String> {
    for part in cookie_header.split(';') {
        let part = part.trim();
        if let Some((k, v)) = part.split_once('=') {
            if k.trim() == name {
                return Some(v.trim().to_string());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{HeaderMap, HeaderValue};

    fn make_filter(enabled: bool) -> Ja3Filter {
        Ja3Filter::new([0u8; 32], enabled)
    }

    fn headers_with_ua(ua: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert("user-agent", HeaderValue::from_str(ua).unwrap());
        h.insert("accept-language", HeaderValue::from_static("en-US"));
        h.insert("accept-encoding", HeaderValue::from_static("gzip"));
        h
    }

    #[test]
    fn test_blocks_curl_ua() {
        let f = make_filter(false);
        let h = headers_with_ua("curl/7.68.0");
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        assert!(f.check(&h, ip).is_err());
    }

    #[test]
    fn test_allows_browser_ua() {
        let f = make_filter(false);
        let h = headers_with_ua("Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0");
        let ip: IpAddr = "10.0.0.2".parse().unwrap();
        assert!(f.check(&h, ip).is_ok());
    }

    #[test]
    fn test_missing_accept_language_rejected() {
        let f = make_filter(false);
        let mut h = HeaderMap::new();
        h.insert("user-agent", HeaderValue::from_static("Mozilla/5.0"));
        h.insert("accept-encoding", HeaderValue::from_static("gzip"));
        let ip: IpAddr = "10.0.0.3".parse().unwrap();
        assert!(f.check(&h, ip).is_err());
    }

    #[test]
    fn test_cookie_challenge_issues_token() {
        let f = make_filter(true);
        let h = headers_with_ua("Mozilla/5.0");
        let ip: IpAddr = "10.0.0.4".parse().unwrap();
        let result = f.check(&h, ip).unwrap();
        assert!(result.is_some());
    }

    #[test]
    fn test_valid_cookie_accepted() {
        let f = make_filter(true);
        let ip: IpAddr = "10.0.0.5".parse().unwrap();
        // 先获取 token
        let h1 = headers_with_ua("Mozilla/5.0");
        let token = f.check(&h1, ip).unwrap().unwrap();
        // 携带 cookie 再次请求
        let mut h2 = headers_with_ua("Mozilla/5.0");
        h2.insert(
            "cookie",
            HeaderValue::from_str(&format!("zfsg_token={}", token)).unwrap(),
        );
        let result = f.check(&h2, ip).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_blocks_python_ua() {
        let f = make_filter(false);
        let h = headers_with_ua("python-requests/2.28.0");
        let ip: IpAddr = "10.0.0.6".parse().unwrap();
        assert!(f.check(&h, ip).is_err());
    }
}
