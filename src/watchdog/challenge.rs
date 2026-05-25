//! 挑战-响应密钥交换
//!
//! 流程：
//! 1. 客户端请求 /gateway/challenge → 服务端生成 32 字节随机挑战
//! 2. 客户端计算 HMAC-SHA256(内置密钥, 挑战) → 发送到 /gateway/challenge/verify
//! 3. 服务端验证 HMAC，签发临时密钥和会话 ID
//! 4. 后续所有请求使用临时密钥加密，内置密钥不再直接用于加密

use std::net::IpAddr;
use std::time::Instant;

use dashmap::DashMap;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

/// DashMap 容量上限
const MAX_PENDING_CHALLENGES: usize = 10_000;
const MAX_SESSIONS: usize = 100_000;

/// 待验证的挑战（绑定客户端 IP，防止跨 IP 重放）
struct PendingChallenge {
    challenge: [u8; 32],
    created_at: Instant,
    client_ip: IpAddr,
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

/// 挑战-响应管理器
pub struct ChallengeManager {
    /// 内置预共享密钥（仅用于握手验证）
    builtin_key: [u8; 32],
    /// 待验证的挑战
    pending: DashMap<String, PendingChallenge>,
    /// 活跃会话
    pub sessions: DashMap<String, Session>,
    /// 挑战有效期（秒）
    challenge_timeout: u64,
    /// 会话超时（秒）
    session_timeout: u64,
    /// 最小请求间隔（毫秒）
    pub min_interval_ms: u64,
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
        builtin_key: [u8; 32],
        challenge_timeout: u64,
        session_timeout: u64,
        min_interval_ms: u64,
    ) -> Self {
        Self {
            builtin_key,
            pending: DashMap::new(),
            sessions: DashMap::new(),
            challenge_timeout,
            session_timeout,
            min_interval_ms,
        }
    }

    /// 步骤 1：生成挑战（绑定客户端 IP，检查容量上限）
    ///
    /// 返回 Ok((challenge_id, challenge_bytes)) 或 Err 达到上限
    pub fn create_challenge(&self, client_ip: IpAddr) -> Result<(String, [u8; 32]), &'static str> {
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

        // 计算期望的 HMAC
        let mut mac =
            HmacSha256::new_from_slice(&self.builtin_key).expect("HMAC 密钥创建失败");
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

        tracing::info!(
            "[challenge] 会话已创建: session_id={}, nonce_step={}",
            session_id,
            nonce_step
        );

        Ok((session_id, ephemeral_key))
    }

    /// 获取会话的只读引用
    pub fn get_session(&self, session_id: &str) -> Option<dashmap::mapref::one::Ref<String, Session>> {
        self.sessions.get(session_id)
    }

    /// 获取会话的可变引用
    pub fn get_session_mut(
        &self,
        session_id: &str,
    ) -> Option<dashmap::mapref::one::RefMut<String, Session>> {
        self.sessions.get_mut(session_id)
    }

    /// 检查会话是否过期
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
        ChallengeManager::new([1u8; 32], 60, 300, 10)
    }

    fn ip() -> IpAddr {
        "10.0.0.1".parse().unwrap()
    }

    #[test]
    fn test_create_challenge_returns_unique_ids() {
        let cm = make_manager();
        let mut ids = std::collections::HashSet::new();
        for _ in 0..100 {
            let (id, _) = cm.create_challenge(ip()).unwrap();
            assert!(ids.insert(id), "duplicate challenge ID");
        }
    }

    #[test]
    fn test_verify_valid_hmac_creates_session() {
        let cm = make_manager();
        let (cid, challenge) = cm.create_challenge(ip()).unwrap();

        // 计算正确的 HMAC
        let mut mac = <HmacSha256 as Mac>::new_from_slice(&cm.builtin_key).unwrap();
        mac.update(&challenge);
        let hmac = mac.finalize().into_bytes();

        let result = cm.verify_and_create_session(&cid, &hmac, ip());
        assert!(result.is_ok());
        let (sid, _) = result.unwrap();
        assert!(cm.is_session_valid(&sid));
    }

    #[test]
    fn test_verify_invalid_hmac_rejected() {
        let cm = make_manager();
        let (cid, _) = cm.create_challenge(ip()).unwrap();
        let bad_hmac = [0u8; 32];
        let result = cm.verify_and_create_session(&cid, &bad_hmac, ip());
        assert!(result.is_err());
    }

    #[test]
    fn test_challenge_ip_mismatch_rejected() {
        let cm = make_manager();
        let (cid, challenge) = cm.create_challenge(ip()).unwrap();

        let mut mac = <HmacSha256 as Mac>::new_from_slice(&cm.builtin_key).unwrap();
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
        let (cid, challenge) = cm.create_challenge(ip()).unwrap();
        let mut mac = <HmacSha256 as Mac>::new_from_slice(&cm.builtin_key).unwrap();
        mac.update(&challenge);
        let hmac = mac.finalize().into_bytes();
        let (sid, _) = cm.verify_and_create_session(&cid, &hmac, ip()).unwrap();

        let session = cm.get_session(&sid).unwrap();
        assert_eq!(session.expected_counter, 1);
    }
}
