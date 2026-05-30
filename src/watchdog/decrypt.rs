//! 解密 + 会话校验
//!
//! 接收 Wasm 端加密的请求报文，执行：
//! 1. 解析报文格式：[12B nonce] + [8B rolling_nonce] + [8B timestamp] + [8B counter] + [2B session_id_len] + [session_id] + [ciphertext] + [16B MAC]
//! 2. 查找会话，获取临时密钥
//! 3. HMAC-MAC 验证（先于解密，防伪造）
//! 4. 滚动码 + 时间戳 + 请求计数器校验（防重放、防自动化）
//! 5. AES-GCM 解密
//! 6. 解析明文：[method长度(1字节)] + [method] + [URL长度(2字节)] + [URL] + [Body]

use aes_gcm::{Aes256Gcm, KeyInit, Nonce, aead::Aead};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::net::IpAddr;
use std::sync::Arc;

use super::challenge::ChallengeManager;

type HmacSha256 = Hmac<Sha256>;

/// 解密后的请求
pub struct DecryptedRequest {
    /// 真实请求路径（如 /api/sites）
    pub url: String,
    /// 请求体
    pub body: Vec<u8>,
    /// 推断的 HTTP 方法
    pub method: String,
}

/// 解密错误类型
#[derive(Debug)]
pub enum DecryptError {
    /// 报文格式无效
    InvalidPacket,
    /// 解密失败（密钥不匹配或数据被篡改）
    DecryptionFailed,
    /// 密钥推导失败
    KeyDerivationFailed,
    /// 会话不存在或已过期
    InvalidSession,
    /// MAC 验证失败（报文被篡改或伪造）
    MacVerificationFailed,
    /// 请求计数器不匹配（重放或乱序）
    CounterMismatch,
    /// 请求频率过快
    RequestTooFast,
}

/// 从滚动码和临时密钥推导 AES-256-GCM 密钥
/// 使用 HKDF-SHA256，每次滚动码变化都产生不同的密钥
fn derive_key(ephemeral_key: &[u8; 32], rolling_nonce: u64) -> [u8; 32] {
    let mut info = Vec::new();
    info.extend_from_slice(b"zfsg-encryption-key-");
    info.extend_from_slice(&rolling_nonce.to_le_bytes());

    let hk = hkdf::Hkdf::<Sha256>::new(Some(&rolling_nonce.to_le_bytes()), ephemeral_key);
    let mut key = [0u8; 32];
    hk.expand(&info, &mut key).expect("HKDF 密钥推导失败");
    key
}

/// 验证 HMAC-MAC（常量时间比较）
fn verify_mac(
    ephemeral_key: &[u8; 32],
    rolling_nonce: u64,
    timestamp: u64,
    request_counter: u64,
    ciphertext: &[u8],
    expected_tag: &[u8; 16],
) -> bool {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(ephemeral_key).expect("HMAC 密钥创建失败");
    mac.update(&rolling_nonce.to_le_bytes());
    mac.update(&timestamp.to_le_bytes());
    mac.update(&request_counter.to_le_bytes());
    mac.update(ciphertext);
    let result = mac.finalize().into_bytes();

    use subtle::ConstantTimeEq;
    let eq: bool = result[..16].ct_eq(expected_tag).into();
    eq
}

/// 解密器
pub struct Decryptor {
    /// 挑战-响应管理器（会话和临时密钥）
    challenge_manager: Arc<ChallengeManager>,
    /// 滚动码最大允许跳跃
    max_nonce_jump: u64,
    /// 最小请求间隔（毫秒）
    min_interval_ms: u64,
}

impl Decryptor {
    pub fn new(
        challenge_manager: Arc<ChallengeManager>,
        max_nonce_jump: u64,
        min_interval_ms: u64,
    ) -> Self {
        Self {
            challenge_manager,
            max_nonce_jump,
            min_interval_ms,
        }
    }

    /// 校验滚动码是否是固定步长的合法前进
    fn is_valid_forward_progress(&self, prev: u64, current: u64, nonce_step: u64) -> bool {
        if current == prev {
            return false;
        }
        let delta = current.wrapping_sub(prev);
        if !delta.is_multiple_of(nonce_step) {
            return false;
        }
        let jumps = delta / nonce_step;
        jumps >= 1 && jumps <= self.max_nonce_jump
    }

    /// 解密 /gateway/encrypted_relay 报文
    pub fn decrypt(&self, ip: IpAddr, packet: &[u8]) -> Result<DecryptedRequest, DecryptError> {
        tracing::info!("[decrypt] 收到报文: {} 字节, IP={}", packet.len(), ip);

        // 1. 解析报文头部：[12B nonce] + [8B rolling_nonce] + [8B timestamp] + [8B counter] + [2B session_id_len]
        if packet.len() < 38 {
            tracing::warn!("[decrypt] 报文太短: {} < 38", packet.len());
            return Err(DecryptError::InvalidPacket);
        }

        let nonce_bytes: [u8; 12] = packet[..12]
            .try_into()
            .map_err(|_| DecryptError::InvalidPacket)?;
        let rolling_nonce = u64::from_le_bytes(
            packet[12..20]
                .try_into()
                .map_err(|_| DecryptError::InvalidPacket)?,
        );
        let timestamp = u64::from_le_bytes(
            packet[20..28]
                .try_into()
                .map_err(|_| DecryptError::InvalidPacket)?,
        );
        let request_counter = u64::from_le_bytes(
            packet[28..36]
                .try_into()
                .map_err(|_| DecryptError::InvalidPacket)?,
        );
        let session_id_len = u16::from_le_bytes(
            packet[36..38]
                .try_into()
                .map_err(|_| DecryptError::InvalidPacket)?,
        ) as usize;

        if packet.len() < 38 + session_id_len + 16 {
            tracing::warn!(
                "[decrypt] 报文太短: {} < {} (session_id + MAC)",
                packet.len(),
                38 + session_id_len + 16
            );
            return Err(DecryptError::InvalidPacket);
        }

        let session_id = std::str::from_utf8(&packet[38..38 + session_id_len])
            .map_err(|_| DecryptError::InvalidPacket)?;
        let ciphertext = &packet[38 + session_id_len..packet.len() - 16];
        let mac_tag: [u8; 16] = packet[packet.len() - 16..]
            .try_into()
            .map_err(|_| DecryptError::InvalidPacket)?;

        tracing::info!(
            "[decrypt] session_id={}, rolling_nonce={}, timestamp={}, counter={}, 密文长度={}, IP={}",
            session_id,
            rolling_nonce,
            timestamp,
            request_counter,
            ciphertext.len(),
            ip
        );

        // 2. 查找会话（直接获取可变引用，避免 TOCTOU 竞态）
        let mut session = self
            .challenge_manager
            .get_session_mut(session_id)
            .ok_or_else(|| {
                tracing::warn!("[decrypt] 会话不存在: session_id={}, IP={}", session_id, ip);
                DecryptError::InvalidSession
            })?;

        // 检查会话是否过期
        if session.created_at.elapsed().as_secs() > self.challenge_manager.session_timeout() {
            tracing::warn!("[decrypt] 会话已过期: session_id={}, IP={}", session_id, ip);
            return Err(DecryptError::InvalidSession);
        }

        let ephemeral_key = session.ephemeral_key;

        // 3. HMAC-MAC 验证（先于解密，防止报文伪造）
        if !verify_mac(
            &ephemeral_key,
            rolling_nonce,
            timestamp,
            request_counter,
            ciphertext,
            &mac_tag,
        ) {
            tracing::warn!(
                "[decrypt] MAC 验证失败: session_id={}, IP={}",
                session_id,
                ip
            );
            return Err(DecryptError::MacVerificationFailed);
        }

        // 4. 校验计数器和滚动码（持有可变引用，原子操作）
        // 请求计数器校验（必须严格递增 +1）
        if request_counter != session.expected_counter {
            tracing::warn!(
                "[decrypt] 计数器不匹配: got={}, expected={}, IP={}",
                request_counter,
                session.expected_counter,
                ip
            );
            return Err(DecryptError::CounterMismatch);
        }

        // 最小请求间隔校验
        let elapsed_ms = session.last_request_instant.elapsed().as_millis() as u64;
        if session.last_timestamp > 0 && elapsed_ms < self.min_interval_ms {
            tracing::warn!(
                "[decrypt] 请求过快: {}ms < {}ms, IP={}",
                elapsed_ms,
                self.min_interval_ms,
                ip
            );
            return Err(DecryptError::RequestTooFast);
        }

        // 滚动码校验
        if session.rolling_nonce > 0
            && !self.is_valid_forward_progress(
                session.rolling_nonce,
                rolling_nonce,
                session.nonce_step,
            )
        {
            tracing::warn!(
                "[decrypt] 非法 rolling_nonce={}, last={}, step={}, IP={}",
                rolling_nonce,
                session.rolling_nonce,
                session.nonce_step,
                ip
            );
            return Err(DecryptError::DecryptionFailed);
        }

        // 防重放：时间戳必须严格递增
        if timestamp <= session.last_timestamp {
            tracing::warn!(
                "[decrypt] 重放攻击! timestamp={} <= last_timestamp={}, IP={}",
                timestamp,
                session.last_timestamp,
                ip
            );
            return Err(DecryptError::DecryptionFailed);
        }

        // 5. 用临时密钥推导 AES 密钥并解密
        let key = derive_key(&ephemeral_key, rolling_nonce);
        let cipher =
            Aes256Gcm::new_from_slice(&key).map_err(|_| DecryptError::KeyDerivationFailed)?;

        let mut aad = Vec::with_capacity(24);
        aad.extend_from_slice(&rolling_nonce.to_le_bytes());
        aad.extend_from_slice(&timestamp.to_le_bytes());
        aad.extend_from_slice(&request_counter.to_le_bytes());

        let plaintext = cipher
            .decrypt(
                Nonce::from_slice(&nonce_bytes),
                aes_gcm::aead::Payload {
                    msg: ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|e| {
                tracing::warn!("[decrypt] 解密失败: {:?}, IP={}", e, ip);
                DecryptError::DecryptionFailed
            })?;

        // 6. 更新会话状态（session 的 RefMut 在此自动释放）
        session.rolling_nonce = rolling_nonce;
        session.last_timestamp = timestamp;
        session.last_request_instant = std::time::Instant::now();
        session.expected_counter += 1;
        drop(session); // 显式释放锁，确保后续操作不持有 DashMap 引用

        // 7. 解析明文：[method长度(1字节)] + [method] + [URL长度(2字节)] + [URL] + [Body]
        if plaintext.len() < 3 {
            return Err(DecryptError::InvalidPacket);
        }
        let method_len = plaintext[0] as usize;
        if plaintext.len() < 1 + method_len + 2 {
            return Err(DecryptError::InvalidPacket);
        }
        let method = String::from_utf8_lossy(&plaintext[1..1 + method_len]).to_string();
        let url_offset = 1 + method_len;
        let url_len =
            u16::from_le_bytes([plaintext[url_offset], plaintext[url_offset + 1]]) as usize;
        if plaintext.len() < url_offset + 2 + url_len {
            return Err(DecryptError::InvalidPacket);
        }
        let url = String::from_utf8_lossy(&plaintext[url_offset + 2..url_offset + 2 + url_len])
            .to_string();
        let body = plaintext[url_offset + 2 + url_len..].to_vec();

        tracing::info!(
            "解密成功: {} {}, rolling_nonce={}, counter={}, IP={}",
            method,
            url,
            rolling_nonce,
            request_counter,
            ip
        );

        Ok(DecryptedRequest { url, body, method })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::watchdog::challenge::ChallengeManager;
    use aes_gcm::{Aes256Gcm, KeyInit, Nonce, aead::Aead};
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    use std::net::IpAddr;
    use std::sync::Arc;

    type HmacSha256 = Hmac<Sha256>;

    fn ip() -> IpAddr {
        "10.0.0.1".parse().unwrap()
    }

    /// 创建一个已建立会话的 Decryptor，返回 (decryptor, session_id, ephemeral_key)
    fn setup_session() -> (Decryptor, String, [u8; 32]) {
        let cm = Arc::new(ChallengeManager::new(60, 300, 0, 60, 100));
        let bootstrap_hex = cm.create_bootstrap_token(ip()).unwrap();
        let (cid, challenge) = cm.create_challenge(ip(), &bootstrap_hex).unwrap();
        let bootstrap_bytes = hex::decode(&bootstrap_hex).unwrap();
        let mut mac = <HmacSha256 as Mac>::new_from_slice(&bootstrap_bytes).unwrap();
        mac.update(&challenge);
        let hmac = mac.finalize().into_bytes();
        let (sid, ekey) = cm.verify_and_create_session(&cid, &hmac, ip()).unwrap();
        let decryptor = Decryptor::new(cm, 10, 0);
        (decryptor, sid, ekey)
    }

    /// 构造一个合法的加密报文
    fn build_packet(
        ephemeral_key: &[u8; 32],
        session_id: &str,
        rolling_nonce: u64,
        timestamp: u64,
        counter: u64,
        method: &str,
        url: &str,
        body: &[u8],
    ) -> Vec<u8> {
        // 构造明文
        let mut plaintext = Vec::new();
        plaintext.push(method.len() as u8);
        plaintext.extend_from_slice(method.as_bytes());
        let url_bytes = url.as_bytes();
        plaintext.extend_from_slice(&(url_bytes.len() as u16).to_le_bytes());
        plaintext.extend_from_slice(url_bytes);
        plaintext.extend_from_slice(body);

        // 推导密钥
        let mut info = Vec::new();
        info.extend_from_slice(b"zfsg-encryption-key-");
        info.extend_from_slice(&rolling_nonce.to_le_bytes());
        let hk = hkdf::Hkdf::<sha2::Sha256>::new(Some(&rolling_nonce.to_le_bytes()), ephemeral_key);
        let mut key = [0u8; 32];
        hk.expand(&info, &mut key).unwrap();

        // AES-GCM 加密
        let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
        let mut nonce_bytes = [0u8; 12];
        getrandom::getrandom(&mut nonce_bytes).unwrap();
        let mut aad = Vec::new();
        aad.extend_from_slice(&rolling_nonce.to_le_bytes());
        aad.extend_from_slice(&timestamp.to_le_bytes());
        aad.extend_from_slice(&counter.to_le_bytes());
        let ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&nonce_bytes),
                aes_gcm::aead::Payload {
                    msg: &plaintext,
                    aad: &aad,
                },
            )
            .unwrap();

        // 计算 HMAC-MAC
        let mut mac = <HmacSha256 as Mac>::new_from_slice(ephemeral_key).unwrap();
        mac.update(&rolling_nonce.to_le_bytes());
        mac.update(&timestamp.to_le_bytes());
        mac.update(&counter.to_le_bytes());
        mac.update(&ciphertext);
        let mac_bytes = mac.finalize().into_bytes();
        let mac_tag: [u8; 16] = mac_bytes[..16].try_into().unwrap();

        // 组装报文
        let mut packet = Vec::new();
        packet.extend_from_slice(&nonce_bytes);
        packet.extend_from_slice(&rolling_nonce.to_le_bytes());
        packet.extend_from_slice(&timestamp.to_le_bytes());
        packet.extend_from_slice(&counter.to_le_bytes());
        let sid_bytes = session_id.as_bytes();
        packet.extend_from_slice(&(sid_bytes.len() as u16).to_le_bytes());
        packet.extend_from_slice(sid_bytes);
        packet.extend_from_slice(&ciphertext);
        packet.extend_from_slice(&mac_tag);
        packet
    }

    #[test]
    fn test_valid_packet_decrypts_correctly() {
        let cm = Arc::new(ChallengeManager::new(60, 300, 0, 60, 100));
        let bootstrap_hex = cm.create_bootstrap_token(ip()).unwrap();
        let (cid, challenge) = cm.create_challenge(ip(), &bootstrap_hex).unwrap();
        let bootstrap_bytes = hex::decode(&bootstrap_hex).unwrap();
        let mut mac = <HmacSha256 as Mac>::new_from_slice(&bootstrap_bytes).unwrap();
        mac.update(&challenge);
        let hmac_bytes = mac.finalize().into_bytes();
        let (sid, ekey) = cm
            .verify_and_create_session(&cid, &hmac_bytes, ip())
            .unwrap();
        let session = cm.get_session(&sid).unwrap();
        let step = session.nonce_step;
        drop(session);

        let decryptor = Decryptor::new(cm, 10, 0);
        let packet = build_packet(&ekey, &sid, step, 1000, 1, "GET", "/api/sites", b"");
        let result = decryptor.decrypt(ip(), &packet);
        assert!(result.is_ok());
        let req = result.unwrap();
        assert_eq!(req.method, "GET");
        assert_eq!(req.url, "/api/sites");
    }

    #[test]
    fn test_tampered_mac_rejected() {
        let cm = Arc::new(ChallengeManager::new(60, 300, 0, 60, 100));
        let bootstrap_hex = cm.create_bootstrap_token(ip()).unwrap();
        let (cid, challenge) = cm.create_challenge(ip(), &bootstrap_hex).unwrap();
        let bootstrap_bytes = hex::decode(&bootstrap_hex).unwrap();
        let mut mac = <HmacSha256 as Mac>::new_from_slice(&bootstrap_bytes).unwrap();
        mac.update(&challenge);
        let hmac_bytes = mac.finalize().into_bytes();
        let (sid, ekey) = cm
            .verify_and_create_session(&cid, &hmac_bytes, ip())
            .unwrap();
        let session = cm.get_session(&sid).unwrap();
        let step = session.nonce_step;
        drop(session);

        let decryptor = Decryptor::new(cm, 10, 0);
        let mut packet = build_packet(&ekey, &sid, step, 1000, 1, "GET", "/api/test", b"");
        // 篡改 MAC 的最后一个字节
        let last = packet.len() - 1;
        packet[last] ^= 0xFF;
        let result = decryptor.decrypt(ip(), &packet);
        assert!(matches!(result, Err(DecryptError::MacVerificationFailed)));
    }

    #[test]
    fn test_packet_too_short_rejected() {
        let (decryptor, _, _) = setup_session();
        let result = decryptor.decrypt(ip(), &[0u8; 10]);
        assert!(matches!(result, Err(DecryptError::InvalidPacket)));
    }

    #[test]
    fn test_counter_mismatch_rejected() {
        let cm = Arc::new(ChallengeManager::new(60, 300, 0, 60, 100));
        let bootstrap_hex = cm.create_bootstrap_token(ip()).unwrap();
        let (cid, challenge) = cm.create_challenge(ip(), &bootstrap_hex).unwrap();
        let bootstrap_bytes = hex::decode(&bootstrap_hex).unwrap();
        let mut mac = <HmacSha256 as Mac>::new_from_slice(&bootstrap_bytes).unwrap();
        mac.update(&challenge);
        let hmac_bytes = mac.finalize().into_bytes();
        let (sid, ekey) = cm
            .verify_and_create_session(&cid, &hmac_bytes, ip())
            .unwrap();
        let session = cm.get_session(&sid).unwrap();
        let step = session.nonce_step;
        drop(session);

        let decryptor = Decryptor::new(cm, 10, 0);
        // counter=1 成功
        let p1 = build_packet(&ekey, &sid, step, 1000, 1, "GET", "/api/a", b"");
        assert!(decryptor.decrypt(ip(), &p1).is_ok());
        // counter=3 跳过了 2，应失败
        let next_nonce = step.wrapping_add(step);
        let p3 = build_packet(&ekey, &sid, next_nonce, 1001, 3, "GET", "/api/b", b"");
        assert!(matches!(
            decryptor.decrypt(ip(), &p3),
            Err(DecryptError::CounterMismatch)
        ));
    }

    #[test]
    fn test_invalid_session_rejected() {
        let (decryptor, _, ekey) = setup_session();
        let packet = build_packet(
            &ekey,
            "nonexistent_session_id",
            1,
            1000,
            1,
            "GET",
            "/api/test",
            b"",
        );
        let result = decryptor.decrypt(ip(), &packet);
        assert!(matches!(result, Err(DecryptError::InvalidSession)));
    }

    #[test]
    fn test_sequential_requests_succeed() {
        let cm = Arc::new(ChallengeManager::new(60, 300, 0, 60, 100));
        let bootstrap_hex = cm.create_bootstrap_token(ip()).unwrap();
        let (cid, challenge) = cm.create_challenge(ip(), &bootstrap_hex).unwrap();
        let bootstrap_bytes = hex::decode(&bootstrap_hex).unwrap();
        let mut mac = <HmacSha256 as Mac>::new_from_slice(&bootstrap_bytes).unwrap();
        mac.update(&challenge);
        let hmac_bytes = mac.finalize().into_bytes();
        let (sid, ekey) = cm
            .verify_and_create_session(&cid, &hmac_bytes, ip())
            .unwrap();

        // 获取 nonce_step 以构造合法的 rolling_nonce
        let session = cm.get_session(&sid).unwrap();
        let nonce_step = session.nonce_step;
        drop(session);

        let decryptor = Decryptor::new(cm, 10, 0);
        for i in 1..=5u64 {
            let rolling = nonce_step.wrapping_mul(i);
            let packet = build_packet(&ekey, &sid, rolling, 1000 + i, i, "GET", "/api/test", b"");
            let result = decryptor.decrypt(ip(), &packet);
            assert!(result.is_ok(), "counter {} should succeed", i);
        }
    }
}
