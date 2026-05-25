//! AES-256-GCM 全量加密 + HMAC-MAC 完整性校验
//!
//! 核心流程：
//! 1. 从滚动码 + 临时密钥推导 AES-256-GCM 密钥（HKDF）
//! 2. 组装明文：[URL长度(2字节) + URL + Body]
//! 3. AES-GCM 加密，输出密文 + 12字节随机 nonce
//! 4. 计算 HMAC-MAC 覆盖 rolling_nonce + timestamp + counter + ciphertext

use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};
use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::memory_pool::MemoryPool;

type HmacSha256 = Hmac<Sha256>;

/// 加密后的载荷
pub struct EncryptedPayload {
    /// 加密的 URL + Body（末尾自动附带 16 字节 AES-GCM tag）
    pub ciphertext: Vec<u8>,
    /// 12 字节随机 nonce（AES-GCM 标准）
    pub nonce: [u8; 12],
}

/// 从滚动码和临时密钥推导 AES-256-GCM 密钥
fn derive_key(ephemeral_key: &[u8; 32], rolling_nonce: u64) -> [u8; 32] {
    let mut info = Vec::new();
    info.extend_from_slice(b"zfsg-encryption-key-");
    info.extend_from_slice(&rolling_nonce.to_le_bytes());

    let hk = Hkdf::<Sha256>::new(Some(&rolling_nonce.to_le_bytes()), ephemeral_key);
    let mut key = [0u8; 32];
    hk.expand(&info, &mut key).expect("HKDF 密钥推导失败");
    key
}

/// 计算 16 字节 HMAC-MAC 标签
///
/// MAC 覆盖：rolling_nonce || timestamp || request_counter || ciphertext
fn compute_mac(
    ephemeral_key: &[u8; 32],
    rolling_nonce: u64,
    timestamp: u64,
    request_counter: u64,
    ciphertext: &[u8],
) -> [u8; 16] {
    let mut mac =
        <HmacSha256 as Mac>::new_from_slice(ephemeral_key).expect("HMAC 密钥创建失败");
    mac.update(&rolling_nonce.to_le_bytes());
    mac.update(&timestamp.to_le_bytes());
    mac.update(&request_counter.to_le_bytes());
    mac.update(ciphertext);
    let result = mac.finalize().into_bytes();
    let mut tag = [0u8; 16];
    tag.copy_from_slice(&result[..16]);
    tag
}

/// 加密请求：Method + URL + Body → AES-GCM 密文
pub fn encrypt_request(
    method: &str,
    url: &str,
    body: &[u8],
    rolling_nonce: u64,
    timestamp: u64,
    ephemeral_key: &[u8; 32],
) -> EncryptedPayload {
    // 1. 推导密钥
    let key_bytes = derive_key(ephemeral_key, rolling_nonce);
    let cipher = Aes256Gcm::new_from_slice(&key_bytes).expect("AES-GCM 密钥创建失败");

    // 2. 生成 12 字节随机 nonce
    let mut nonce_bytes = [0u8; 12];
    getrandom::getrandom(&mut nonce_bytes).expect("nonce 随机生成失败");

    // 3. 组装明文：[method长度(1字节)] + [method] + [URL长度(2字节)] + [URL] + [Body]
    let method_bytes = method.as_bytes();
    let url_bytes = url.as_bytes();
    let url_len = (url_bytes.len() as u16).to_le_bytes();
    let mut plaintext =
        Vec::with_capacity(1 + method_bytes.len() + 2 + url_bytes.len() + body.len());
    plaintext.push(method_bytes.len() as u8);
    plaintext.extend_from_slice(method_bytes);
    plaintext.extend_from_slice(&url_len);
    plaintext.extend_from_slice(url_bytes);
    plaintext.extend_from_slice(body);

    // 4. 构建 AAD（附加认证数据）
    let mut aad = Vec::with_capacity(24);
    aad.extend_from_slice(&rolling_nonce.to_le_bytes());
    aad.extend_from_slice(&timestamp.to_le_bytes());

    // 5. AES-GCM 加密
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce_bytes),
            aes_gcm::aead::Payload {
                msg: plaintext.as_ref(),
                aad: &aad,
            },
        )
        .expect("AES-GCM 加密失败");

    EncryptedPayload {
        ciphertext,
        nonce: nonce_bytes,
    }
}

/// 构建完整的加密请求包
///
/// 输出格式：
/// [12B nonce] + [8B rolling_nonce] + [8B timestamp] + [8B counter] + [2B session_id_len] + [session_id] + [ciphertext] + [16B MAC]
pub fn build_encrypted_request(
    original_url: &str,
    method: &str,
    body: &[u8],
    pool: &mut MemoryPool,
    session_id: &str,
    request_counter: u64,
) -> Result<(String, Vec<u8>), &'static str> {
    // 1. 更新滚动码
    pool.update_nonce();
    let nonce = pool.current_nonce();

    // 2. 获取毫秒时间戳
    let timestamp = js_sys::Date::now() as u64;

    // 3. AES-GCM 加密
    let payload = encrypt_request(method, original_url, body, nonce, timestamp, pool.hash_key());

    // 4. 计算 HMAC-MAC
    let mac_tag = compute_mac(
        pool.hash_key(),
        nonce,
        timestamp,
        request_counter,
        &payload.ciphertext,
    );

    // 5. 组装最终报文
    let session_id_bytes = session_id.as_bytes();
    let session_id_len = (session_id_bytes.len() as u16).to_le_bytes();

    let mut final_packet = Vec::with_capacity(
        12 + 8 + 8 + 8 + 2 + session_id_bytes.len() + payload.ciphertext.len() + 16,
    );
    final_packet.extend_from_slice(&payload.nonce); // 12B
    final_packet.extend_from_slice(&nonce.to_le_bytes()); // 8B
    final_packet.extend_from_slice(&timestamp.to_le_bytes()); // 8B
    final_packet.extend_from_slice(&request_counter.to_le_bytes()); // 8B
    final_packet.extend_from_slice(&session_id_len); // 2B
    final_packet.extend_from_slice(session_id_bytes); // 变长
    final_packet.extend_from_slice(&payload.ciphertext); // 变长
    final_packet.extend_from_slice(&mac_tag); // 16B

    // 目标：网关的加密中继端点
    let origin = crate::gateway_origin().unwrap_or("http://localhost:3000");
    let relay_url = format!("{}/gateway/encrypted_relay", origin);
    Ok((relay_url, final_packet))
}

// HKDF 导入（用于 derive_key）
use hkdf::Hkdf;
