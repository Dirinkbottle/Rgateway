//! 挑战-响应密钥交换（Bootstrap Token 模式）
//!
//! 流程：
//! 1. 客户端请求 /gateway/bootstrap → 服务端签发短期一次性 bootstrap token
//! 2. 客户端请求 /gateway/challenge（携带 bootstrap token）→ 服务端生成 32 字节随机挑战
//! 3. 客户端计算 HMAC-SHA256(bootstrap_token, 挑战) → 发送到 /gateway/challenge/verify
//! 4. 服务端验证 HMAC，签发临时密钥和会话 ID
//! 5. 后续所有请求使用临时密钥加密

use std::net::IpAddr;
use std::time::Instant;

use dashmap::DashMap;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

/// DashMap 容量上限
const MAX_PENDING_CHALLENGES: usize = 10_000;
const MAX_SESSIONS: usize = 100_000;
const MAX_BOOTSTRAP_TOKENS: usize = 10_000;

/// 待验证的挑战（绑定客户端 IP，防止跨 IP 重放）
struct PendingChallenge {
    challenge: [u8; 32],
    created_at: Instant,
    client_ip: IpAddr,
    /// 关联的 bootstrap token（用于 HMAC 验证）
    bootstrap_token: [u8; 32],
}

/// Bootstrap Token（短期一次性，用于挑战握手）
pub struct BootstrapToken {
    pub token: [u8; 32],
    pub created_at: Instant,
    pub client_ip: IpAddr,
    pub used: bool,
}

/// 活跃会话（按会话 ID 索引）
pub struct Session {
    /// 临时密钥（仅用于本次会话的加密）
    pub ephemeral_key: [u8; 32],
    /// 会话创建时间
    pub created_at: Instant,
    /// 期望的下一个请求计数器值
    pub expected_counter: u64,
    /// 上次请求的时间戳（毫秒，来自报文）
    pub last_timestamp: u64,
    /// 上次请求的墙钟时间（用于最小间隔校验）
    pub last_request_instant: Instant,
    /// 当前滚动码
    pub rolling_nonce: u64,
    /// 固定步长（由临时密钥派生）
    pub nonce_step: u64,
}

/// Bootstrap 速率限制记录
struct BootstrapRateEntry {
    count: u32,
    window_start: Instant,
}

/// 挑战-响应管理器
#[allow(dead_code)]
pub struct ChallengeManager {
    /// 待验证的挑战
    pending: DashMap<String, PendingChallenge>,
    /// 活跃会话
    pub sessions: DashMap<String, Session>,
    /// Bootstrap token 存储
    bootstrap_tokens: DashMap<String, BootstrapToken>,
    /// Bootstrap 速率限制（每 IP 每分钟）
    bootstrap_rate: DashMap<IpAddr, BootstrapRateEntry>,
    /// 挑战有效期（秒）
    challenge_timeout: u64,
    /// 会话超时（秒）
    session_timeout: u64,
    /// 最小请求间隔（毫秒）
    pub min_interval_ms: u64,
    /// Bootstrap token 有效期（秒）
    bootstrap_ttl: u64,
    /// Bootstrap 每分钟每 IP 限流
    bootstrap_rate_limit: u32,
}

/// 从密钥派生固定步长
fn derive_nonce_step(key: &[u8; 32]) -> u64 {
    let mut hasher = Sha256::new();
    hasher.update(key);
    let hash = hasher.finalize();
    let step = u64::from_le_bytes(hash[..8].try_into().expect("步长哈希切片长度正确"));
    if step == 0 {
        1
    } else {
        step
    }
}

/// 生成 32 字节随机 ID（hex 编码返回）
fn random_hex_id() -> String {
    let mut buf = [0u8; 16];
    getrandom::getrandom(&mut buf).expect("随机数生成失败");
    hex::encode(buf)
}

/// 生成 32 字节随机字节
fn random_bytes_32() -> [u8; 32] {
    let mut buf = [0u8; 32];
    getrandom::getrandom(&mut buf).expect("随机数生成失败");
    buf
}

impl ChallengeManager {
    pub fn new(
        challenge_timeout: u64,
        session_timeout: u64,
        min_interval_ms: u64,
        bootstrap_ttl: u64,
        bootstrap_rate_limit: u32,
    ) -> Self {
        Self {
            pending: DashMap::new(),
            sessions: DashMap::new(),
            bootstrap_tokens: DashMap::new(),
            bootstrap_rate: DashMap::new(),
            challenge_timeout,
            session_timeout,
            min_interval_ms,
            bootstrap_ttl,
            bootstrap_rate_limit,
        }
    }

    /// 创建 Bootstrap Token（短期一次性，绑定客户端 IP）
    ///
    /// 返回 Ok(token_hex) 或 Err 达到限流/容量上限
    pub fn create_bootstrap_token(&self, client_ip: IpAddr) -> Result<String, &'static str> {
        // 速率限制：每 IP 每分钟 N 次
        {
            let mut entry = self.bootstrap_rate.entry(client_ip).or_insert_with(|| {
                BootstrapRateEntry {
                    count: 0,
                    window_start: Instant::now(),
                }
            });
            if entry.window_start.elapsed().as_secs() >= 60 {
                // 窗口重置
                entry.count = 0;
                entry.window_start = Instant::now();
            }
            if entry.count >= self.bootstrap_rate_limit {
                return Err("Bootstrap 请求过于频繁，请稍后重试");
            }
            entry.count += 1;
        }

        // 容量检查
        if self.bootstrap_tokens.len() >= MAX_BOOTSTRAP_TOKENS {
            self.cleanup_bootstrap_tokens();
            if self.bootstrap_tokens.len() >= MAX_BOOTSTRAP_TOKENS {
                return Err("Bootstrap 队列已满，请稍后重试");
            }
        }

        let token = random_bytes_32();
        let token_hex = hex::encode(token);

        self.bootstrap_tokens.insert(
            token_hex.clone(),
            BootstrapToken {
                token,
                created_at: Instant::now(),
                client_ip,
                used: false,
            },
        );

        self.cleanup_bootstrap_tokens();

        Ok(token_hex)
    }

    /// 验证 bootstrap token 并标记为已使用
    fn verify_bootstrap_token(
        &self,
        token_hex: &str,
        client_ip: IpAddr,
    ) -> Result<[u8; 32], &'static str> {
        let mut entry = self
            .bootstrap_tokens
            .get_mut(token_hex)
            .ok_or("Bootstrap token 不存在或已过期")?;

        if entry.used {
            return Err("Bootstrap token 已使用");
        }
        if entry.created_at.elapsed().as_secs() > self.bootstrap_ttl {
            return Err("Bootstrap token 已过期");
        }
        if entry.client_ip != client_ip {
            return Err("Bootstrap token IP 不匹配");
        }

        entry.used = true;
        Ok(entry.token)
    }

    /// 清理过期的 bootstrap tokens
    fn cleanup_bootstrap_tokens(&self) {
        let ttl = self.bootstrap_ttl;
        self.bootstrap_tokens
            .retain(|_, v| !v.used && v.created_at.elapsed().as_secs() <= ttl);
    }

    /// 步骤 1：生成挑战（需要有效的 bootstrap token）
    ///
    /// 返回 Ok((challenge_id, challenge_bytes)) 或 Err
    pub fn create_challenge(
        &self,
        client_ip: IpAddr,
        bootstrap_token_hex: &str,
    ) -> Result<(String, [u8; 32]), &'static str> {
        // 验证 bootstrap token
        let bootstrap_token = self.verify_bootstrap_token(bootstrap_token_hex, client_ip)?;

        // 容量检查：防止内存耗尽 DoS
        if self.pending.len() >= MAX_PENDING_CHALLENGES {
            self.cleanup_pending();
            if self.pending.len() >= MAX_PENDING_CHALLENGES {
                return Err("挑战队列已满，请稍后重试");
            }
        }

        let challenge_id = random_hex_id();
        let challenge_bytes = random_bytes_32();

        self.pending.insert(
            challenge_id.clone(),
            PendingChallenge {
                challenge: challenge_bytes,
                created_at: Instant::now(),
                client_ip,
                bootstrap_token,
            },
        );

        // 清理过期挑战
        self.cleanup_pending();

        Ok((challenge_id, challenge_bytes))
    }

    /// 步骤 2：验证客户端响应，签发临时密钥
    ///
    /// 客户端应计算 HMAC-SHA256(builtin_key, challenge_bytes)
    /// client_ip 必须与 create_challenge 时的 IP 一致
    ///
    /// 返回 (session_id, ephemeral_key)
    pub fn verify_and_create_session(
        &self,
        challenge_id: &str,
        client_hmac: &[u8],
        client_ip: IpAddr,
    ) -> Result<(String, [u8; 32]), &'static str> {
        // 取出待验证挑战
        let pending = self
            .pending
            .remove(challenge_id)
            .ok_or("挑战 ID 不存在或已过期")?;

        // 检查挑战是否过期
        if pending.1.created_at.elapsed().as_secs() > self.challenge_timeout {
            return Err("挑战已过期");
        }

        // IP 绑定校验：防止跨 IP 挑战劫持
        if pending.1.client_ip != client_ip {
            tracing::warn!(
                "[challenge] IP 不匹配: expected={}, got={}",
                pending.1.client_ip,
                client_ip
            );
            return Err("挑战 IP 不匹配");
        }

        // 计算期望的 HMAC（使用 bootstrap token 作为密钥）
        let mut mac =
            HmacSha256::new_from_slice(&pending.1.bootstrap_token).expect("HMAC 密钥创建失败");
        mac.update(&pending.1.challenge);
        let expected = mac.finalize().into_bytes();

        // 常量时间比较
        use subtle::ConstantTimeEq;
        let eq: bool = expected
            .as_slice()
            .ct_eq(client_hmac)
            .into();
        if !eq {
            return Err("挑战验证失败：HMAC 不匹配");
        }

        // 容量检查：防止会话泛洪
        if self.sessions.len() >= MAX_SESSIONS {
            self.cleanup_sessions();
            if self.sessions.len() >= MAX_SESSIONS {
                return Err("会话数量已达上限，请稍后重试");
            }
        }

        // 签发临时密钥和会话 ID
        let ephemeral_key = random_bytes_32();
        let session_id = random_hex_id();
        let nonce_step = derive_nonce_step(&ephemeral_key);

        self.sessions.insert(
            session_id.clone(),
            Session {
                ephemeral_key,
                created_at: Instant::now(),
                expected_counter: 1,
                last_timestamp: 0,
                last_request_instant: Instant::now(),
                rolling_nonce: 0,
                nonce_step,
            },
        );

        tracing::info!("[challenge] 会话已创建: session_id={}***", &session_id[..8]);

        Ok((session_id, ephemeral_key))
    }

    /// 获取会话的只读引用
    #[allow(dead_code)]
    pub fn get_session(&self, session_id: &str) -> Option<dashmap::mapref::one::Ref<'_, String, Session>> {
        self.sessions.get(session_id)
    }

    /// 获取会话的可变引用
    pub fn get_session_mut(
        &self,
        session_id: &str,
    ) -> Option<dashmap::mapref::one::RefMut<'_, String, Session>> {
        self.sessions.get_mut(session_id)
    }

    /// 检查会话是否过期
    #[allow(dead_code)]
    pub fn is_session_valid(&self, session_id: &str) -> bool {
        if let Some(session) = self.sessions.get(session_id) {
            session.created_at.elapsed().as_secs() <= self.session_timeout
        } else {
            false
        }
    }

    /// 获取会话超时时间（供外部持有 RefMut 时自行校验）
    pub fn session_timeout(&self) -> u64 {
        self.session_timeout
    }

    /// 清理过期的待验证挑战
    fn cleanup_pending(&self) {
        let timeout = self.challenge_timeout;
        self.pending
            .retain(|_, v| v.created_at.elapsed().as_secs() <= timeout);
    }

    /// 清理过期会话
    pub fn cleanup_sessions(&self) {
        let timeout = self.session_timeout;
        self.sessions
            .retain(|_, v| v.created_at.elapsed().as_secs() <= timeout);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hmac::Mac;
    use std::net::IpAddr;

    fn make_manager() -> ChallengeManager {
        ChallengeManager::new(60, 300, 10, 60, 100)
    }

    fn ip() -> IpAddr {
        "10.0.0.1".parse().unwrap()
    }

    /// 辅助：创建 bootstrap token 并返回 token_hex
    fn get_bootstrap(cm: &ChallengeManager, client_ip: IpAddr) -> String {
        cm.create_bootstrap_token(client_ip).unwrap()
    }

    /// 辅助：创建 bootstrap + challenge，返回 (challenge_id, challenge_bytes, bootstrap_token_bytes)
    fn create_challenge_with_bootstrap(
        cm: &ChallengeManager,
        client_ip: IpAddr,
    ) -> (String, [u8; 32], [u8; 32]) {
        let bootstrap_hex = get_bootstrap(cm, client_ip);
        let (cid, challenge) = cm.create_challenge(client_ip, &bootstrap_hex).unwrap();
        let bootstrap_bytes = hex::decode(&bootstrap_hex).unwrap();
        let mut bt = [0u8; 32];
        bt.copy_from_slice(&bootstrap_bytes);
        (cid, challenge, bt)
    }

    #[test]
    fn test_bootstrap_token_rate_limited() {
        let cm = make_manager();
        let ip = ip();
        // 前 100 次应该成功（默认限流 100/min in test）
        for _ in 0..100 {
            assert!(cm.create_bootstrap_token(ip).is_ok());
        }
        // 第 101 次应被限流
        assert!(cm.create_bootstrap_token(ip).is_err());
    }

    #[test]
    fn test_create_challenge_requires_valid_bootstrap() {
        let cm = make_manager();
        let ip = ip();
        // 没有 bootstrap token 时应失败
        let result = cm.create_challenge(ip, "invalid_token_hex");
        assert!(result.is_err());
    }

    #[test]
    fn test_create_challenge_returns_unique_ids() {
        let cm = make_manager();
        let ip = ip();
        let mut ids = std::collections::HashSet::new();
        for _ in 0..10 {
            let bootstrap = get_bootstrap(&cm, ip);
            let (id, _) = cm.create_challenge(ip, &bootstrap).unwrap();
            assert!(ids.insert(id), "duplicate challenge ID");
        }
    }

    #[test]
    fn test_verify_valid_hmac_creates_session() {
        let cm = make_manager();
        let ip = ip();
        let (cid, challenge, bootstrap_token) = create_challenge_with_bootstrap(&cm, ip);

        // 用 bootstrap_token 计算 HMAC
        let mut mac = <HmacSha256 as Mac>::new_from_slice(&bootstrap_token).unwrap();
        mac.update(&challenge);
        let hmac = mac.finalize().into_bytes();

        let result = cm.verify_and_create_session(&cid, &hmac, ip);
        assert!(result.is_ok());
        let (sid, _) = result.unwrap();
        assert!(cm.is_session_valid(&sid));
    }

    #[test]
    fn test_verify_invalid_hmac_rejected() {
        let cm = make_manager();
        let ip = ip();
        let (cid, _, _) = create_challenge_with_bootstrap(&cm, ip);
        let bad_hmac = [0u8; 32];
        let result = cm.verify_and_create_session(&cid, &bad_hmac, ip);
        assert!(result.is_err());
    }

    #[test]
    fn test_challenge_ip_mismatch_rejected() {
        let cm = make_manager();
        let ip = ip();
        let (cid, challenge, bootstrap_token) = create_challenge_with_bootstrap(&cm, ip);

        let mut mac = <HmacSha256 as Mac>::new_from_slice(&bootstrap_token).unwrap();
        mac.update(&challenge);
        let hmac = mac.finalize().into_bytes();

        // 用不同 IP 验证
        let other_ip: IpAddr = "10.0.0.99".parse().unwrap();
        let result = cm.verify_and_create_session(&cid, &hmac, other_ip);
        assert!(result.is_err());
    }

    #[test]
    fn test_session_counter_starts_at_one() {
        let cm = make_manager();
        let ip = ip();
        let (cid, challenge, bootstrap_token) = create_challenge_with_bootstrap(&cm, ip);

        let mut mac = <HmacSha256 as Mac>::new_from_slice(&bootstrap_token).unwrap();
        mac.update(&challenge);
        let hmac = mac.finalize().into_bytes();
        let (sid, _) = cm.verify_and_create_session(&cid, &hmac, ip).unwrap();

        let session = cm.get_session(&sid).unwrap();
        assert_eq!(session.expected_counter, 1);
    }

    #[test]
    fn test_bootstrap_token_single_use() {
        let cm = make_manager();
        let ip = ip();
        let bootstrap_hex = get_bootstrap(&cm, ip);

        // 第一次使用
        let (cid1, _) = cm.create_challenge(ip, &bootstrap_hex).unwrap();
        assert!(!cid1.is_empty());

        // 第二次使用同一 bootstrap token 应失败
        let result = cm.create_challenge(ip, &bootstrap_hex);
        assert!(result.is_err());
    }

    #[test]
    fn test_bootstrap_ip_mismatch_rejected() {
        let cm = make_manager();
        let ip1: IpAddr = "10.0.0.1".parse().unwrap();
        let ip2: IpAddr = "10.0.0.99".parse().unwrap();
        let bootstrap_hex = get_bootstrap(&cm, ip1);

        // 用不同 IP 发起 challenge 应失败
        let result = cm.create_challenge(ip2, &bootstrap_hex);
        assert!(result.is_err());
    }
}
