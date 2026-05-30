//! 日志脱敏工具
//!
//! 生产环境中，session_id、URL 查询参数、IP 等敏感信息不应在 info 级别输出。
//! 本模块提供统一的脱敏函数，确保日志中不泄露安全细节。

use std::net::IpAddr;

/// 脱敏 ID（保留前 4 字符 + ***）
///
/// 示例：`"abcdef123456"` → `"abcd***"`
#[allow(dead_code)]
pub fn redact_id(id: &str) -> String {
    if id.len() <= 4 {
        return "***".to_string();
    }
    format!("{}***", &id[..4])
}

/// 脱敏 URL（保留 path，query 参数替换为 ***）
///
/// 示例：`"/api/sites?category=news&page=1"` → `"/api/sites?***"`
pub fn redact_url(url: &str) -> String {
    match url.split_once('?') {
        Some((path, _)) => format!("{}?***", path),
        None => url.to_string(),
    }
}

/// 脱敏 IPv4（保留前两段）
///
/// 示例：`"192.168.1.100"` → `"192.168.***.***"`
pub fn redact_ip(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            format!("{}.{}.***.***", octets[0], octets[1])
        }
        IpAddr::V6(_) => "***".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_redact_id() {
        assert_eq!(redact_id("abcdef123456"), "abcd***");
        assert_eq!(redact_id("ab"), "***");
        assert_eq!(redact_id(""), "***");
        assert_eq!(redact_id("1234"), "***");
        assert_eq!(redact_id("12345"), "1234***");
    }

    #[test]
    fn test_redact_url() {
        assert_eq!(
            redact_url("/api/sites?category=news&page=1"),
            "/api/sites?***"
        );
        assert_eq!(redact_url("/api/sites"), "/api/sites");
        assert_eq!(redact_url("/health?check=true"), "/health?***");
    }

    #[test]
    fn test_redact_ip_v4() {
        let ip: IpAddr = "192.168.1.100".parse().unwrap();
        assert_eq!(redact_ip(ip), "192.168.***.***");
    }

    #[test]
    fn test_redact_ip_v6() {
        let ip: IpAddr = "::1".parse().unwrap();
        assert_eq!(redact_ip(ip), "***");
    }
}
