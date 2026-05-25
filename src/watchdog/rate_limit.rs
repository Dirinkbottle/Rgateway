//! IP 频率限制
//!
//! 固定窗口计数器算法，O(1) 查找（DashMap）。
//! 超过阈值返回 429，超过封禁阈值直接封禁一段时间。

use dashmap::DashMap;
use std::net::IpAddr;
use std::time::Instant;

use super::config::RateLimitConfig;

/// DashMap 容量上限
const MAX_COUNTERS: usize = 1_000_000;

/// IP 计数器
struct IpCounter {
    /// 当前窗口起始时间
    window_start: Instant,
    /// 当前窗口请求数
    count: u32,
    /// 封禁到期时间
    ban_until: Option<Instant>,
}

/// IP 频率限制器
pub struct RateLimiter {
    /// 按 IP 隔离的计数器
    counters: DashMap<IpAddr, IpCounter>,
    /// 默认每秒请求数
    default_rps: u32,
    /// 触发封禁的阈值
    ban_threshold: u32,
    /// 封禁持续时间
    ban_duration_secs: u64,
    /// 白名单 IP（预解析为 IpAddr 避免运行时分配）
    whitelist: Vec<IpAddr>,
}

impl RateLimiter {
    pub fn new(config: &RateLimitConfig) -> Self {
        let whitelist: Vec<IpAddr> = config
            .whitelist
            .iter()
            .filter_map(|s| s.parse().ok())
            .collect();
        Self {
            counters: DashMap::new(),
            default_rps: config.default_rps,
            ban_threshold: config.ban_threshold,
            ban_duration_secs: config.ban_duration_secs,
            whitelist,
        }
    }

    /// 检查 IP 是否允许通过
    ///
    /// 返回：(是否允许, 剩余配额)
    pub fn check(&self, ip: IpAddr) -> (bool, u32) {
        // 白名单跳过（IpAddr 直接比较，无堆分配）
        if self.whitelist.contains(&ip) {
            return (true, u32::MAX);
        }

        // 容量检查：防止内存耗尽
        if !self.counters.contains_key(&ip) && self.counters.len() >= MAX_COUNTERS {
            // 清理过期窗口后再检查
            self.cleanup_stale_counters();
            if self.counters.len() >= MAX_COUNTERS {
                return (false, 0);
            }
        }

        let mut entry = self.counters.entry(ip).or_insert_with(|| IpCounter {
            window_start: Instant::now(),
            count: 0,
            ban_until: None,
        });

        // 检查封禁状态
        if let Some(ban_until) = entry.ban_until {
            if Instant::now() < ban_until {
                return (false, 0);
            }
            // 封禁到期，重置
            entry.ban_until = None;
            entry.count = 0;
            entry.window_start = Instant::now();
        }

        // 窗口重置（1秒）
        if entry.window_start.elapsed().as_secs() >= 1 {
            entry.count = 0;
            entry.window_start = Instant::now();
        }

        entry.count += 1;

        // 先检查是否超过 RPS 限制（软拒绝）
        if entry.count > self.default_rps {
            // 超过 RPS 后再检查是否达到封禁阈值（硬封禁）
            if entry.count > self.ban_threshold {
                entry.ban_until =
                    Some(Instant::now() + std::time::Duration::from_secs(self.ban_duration_secs));
                tracing::warn!(
                    "IP {} 触发封禁，持续 {} 秒（当前窗口请求数: {}）",
                    ip,
                    self.ban_duration_secs,
                    entry.count
                );
            }
            return (false, 0);
        }

        (true, self.default_rps - entry.count)
    }

    /// 清理过期的计数器条目（窗口超过 2 秒未活跃）
    fn cleanup_stale_counters(&self) {
        self.counters.retain(|_, v| {
            v.window_start.elapsed().as_secs() < 2 && v.ban_until.is_none_or(|u| Instant::now() < u)
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    fn make_limiter(rps: u32, ban_threshold: u32) -> RateLimiter {
        RateLimiter::new(&RateLimitConfig {
            default_rps: rps,
            ban_threshold,
            ban_duration_secs: 5,
            whitelist: vec!["127.0.0.1".to_string()],
        })
    }

    #[test]
    fn test_within_limit_allows() {
        let rl = make_limiter(50, 100);
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        for _ in 0..50 {
            let (allowed, _) = rl.check(ip);
            assert!(allowed);
        }
    }

    #[test]
    fn test_exceed_rps_rejects() {
        let rl = make_limiter(10, 100);
        let ip: IpAddr = "10.0.0.2".parse().unwrap();
        for _ in 0..10 {
            rl.check(ip);
        }
        let (allowed, _) = rl.check(ip);
        assert!(!allowed);
    }

    #[test]
    fn test_whitelist_bypasses_limit() {
        let rl = make_limiter(5, 10);
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        for _ in 0..100 {
            let (allowed, remaining) = rl.check(ip);
            assert!(allowed);
            assert_eq!(remaining, u32::MAX);
        }
    }

    #[test]
    fn test_ban_triggers_after_rps() {
        let rl = make_limiter(10, 15);
        let ip: IpAddr = "10.0.0.3".parse().unwrap();
        // 正常请求
        for _ in 0..10 {
            rl.check(ip);
        }
        // 超过 RPS 但未达 ban
        for _ in 0..5 {
            rl.check(ip);
        }
        // 超过 ban 阈值
        let (allowed, _) = rl.check(ip);
        assert!(!allowed);
    }

    #[test]
    fn test_different_ips_independent() {
        let rl = make_limiter(5, 100);
        let ip1: IpAddr = "10.0.0.10".parse().unwrap();
        let ip2: IpAddr = "10.0.0.11".parse().unwrap();
        for _ in 0..5 {
            rl.check(ip1);
        }
        // ip1 已达限，ip2 应正常
        let (allowed1, _) = rl.check(ip1);
        let (allowed2, _) = rl.check(ip2);
        assert!(!allowed1);
        assert!(allowed2);
    }
}
