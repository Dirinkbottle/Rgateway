//! ZFSG (Zero-Friction Security Gateway) — Wasm 核心模块
//!
//! 编译目标：wasm32-unknown-unknown
//! 功能：Bootstrap Token → 挑战-响应握手获取临时密钥，劫持浏览器 fetch，全量加密请求
//!
//! 安全模型：
//! - 不再内置长期密钥，改为服务端签发短期 bootstrap token
//! - Bootstrap token 一次性使用，有效期 60 秒，绑定客户端 IP
//! - 握手完成后获得临时会话密钥，用于后续加密通信

mod crypto;
mod interceptor;
mod memory_pool;

use std::cell::UnsafeCell;

use base64::Engine;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;

use memory_pool::MemoryPool;

/// 会话状态（挑战-响应握手后获得）
struct SessionState {
    session_id: String,
    _ephemeral_key: [u8; 32],
}

/// 全局内存池包装（Wasm 单线程，UnsafeCell 允许内部可变性）
struct PoolWrapper(UnsafeCell<Option<MemoryPool>>);
unsafe impl Sync for PoolWrapper {}
static POOL: PoolWrapper = PoolWrapper(UnsafeCell::new(None));

/// 网关地址
struct OriginWrapper(UnsafeCell<Option<String>>);
unsafe impl Sync for OriginWrapper {}
static GATEWAY_ORIGIN: OriginWrapper = OriginWrapper(UnsafeCell::new(None));

/// 会话状态
struct SessionWrapper(UnsafeCell<Option<SessionState>>);
unsafe impl Sync for SessionWrapper {}
static SESSION: SessionWrapper = SessionWrapper(UnsafeCell::new(None));

pub fn gateway_origin() -> Option<&'static str> {
    unsafe { &*GATEWAY_ORIGIN.0.get() }.as_deref()
}

/// 获取当前会话 ID
pub fn session_id() -> &'static str {
    unsafe { &*SESSION.0.get() }
        .as_ref()
        .expect("会话未初始化，请先调用 initialize()")
        .session_id
        .as_str()
}

/// 获取内存池的可变引用
unsafe fn pool_mut() -> &'static mut MemoryPool {
    let pool_opt = unsafe { &mut *POOL.0.get() };
    pool_opt
        .as_mut()
        .expect("内存池未初始化，请先调用 initialize()")
}

/// Wasm 模块初始化入口（异步 — Bootstrap + 挑战-响应握手）
///
/// 流程：
/// 1. POST /gateway/bootstrap → 获取短期一次性 bootstrap_token
/// 2. POST /gateway/challenge（携带 X-Bootstrap-Token）→ 获取 challenge_id + challenge_bytes
/// 3. 计算 HMAC-SHA256(bootstrap_token, challenge_bytes)
/// 4. POST /gateway/challenge/verify → 获取 session_id + ephemeral_key
/// 5. 用临时密钥初始化内存池
/// 6. 劫持 window.fetch
#[wasm_bindgen]
pub async fn initialize(gateway_origin: String) {
    // 保存网关地址
    unsafe {
        *GATEWAY_ORIGIN.0.get() = Some(gateway_origin.clone());
    }

    // 步骤 1：获取 bootstrap token（短期一次性，绑定 IP）
    let bootstrap_url = format!("{}/gateway/bootstrap", gateway_origin);
    let bootstrap_resp = js_fetch_post_json(&bootstrap_url, "").await;
    let bootstrap_token_hex = js_json_get_string(&bootstrap_resp, "bootstrap_token");

    web_sys::console::log_1(&"[ZFSG] Bootstrap token 已获取".into());

    // 步骤 2：请求挑战（携带 bootstrap token）
    let challenge_url = format!("{}/gateway/challenge", gateway_origin);
    let resp = js_fetch_post_json_with_header(
        &challenge_url,
        "",
        "X-Bootstrap-Token",
        &bootstrap_token_hex,
    )
    .await;
    let challenge_id = js_json_get_string(&resp, "challenge_id");
    let challenge_b64 = js_json_get_string(&resp, "challenge");
    let challenge_bytes = base64_decode(&challenge_b64);

    web_sys::console::log_1(
        &format!("[ZFSG] 挑战已获取: challenge_id={}", challenge_id).into(),
    );

    // 步骤 3：计算 HMAC-SHA256(bootstrap_token, challenge_bytes)
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    type HmacSha256 = Hmac<Sha256>;

    let bootstrap_token_bytes = base64_decode(&bootstrap_token_hex);
    let mut mac =
        <HmacSha256 as Mac>::new_from_slice(&bootstrap_token_bytes).expect("HMAC 密钥创建失败");
    mac.update(&challenge_bytes);
    let hmac_result = mac.finalize().into_bytes();

    // 步骤 4：发送验证
    let verify_url = format!("{}/gateway/challenge/verify", gateway_origin);
    let hmac_b64 = base64_encode(&hmac_result);
    let body_json = format!(
        r#"{{"challenge_id":"{}","response":"{}"}}"#,
        challenge_id, hmac_b64
    );
    let verify_resp = js_fetch_post_json(&verify_url, &body_json).await;
    let session_id_str = js_json_get_string(&verify_resp, "session_id");
    let ephemeral_key_b64 = js_json_get_string(&verify_resp, "ephemeral_key");
    let ephemeral_key_bytes = base64_decode(&ephemeral_key_b64);

    let mut ephemeral_key = [0u8; 32];
    ephemeral_key.copy_from_slice(&ephemeral_key_bytes);

    web_sys::console::log_1(&"[ZFSG] 安全会话已建立".into());

    // 步骤 5：存储会话状态
    unsafe {
        *SESSION.0.get() = Some(SessionState {
            session_id: session_id_str,
            _ephemeral_key: ephemeral_key,
        });
    }

    // 步骤 6：用临时密钥初始化内存池
    let pool = MemoryPool::new(ephemeral_key);
    unsafe {
        *POOL.0.get() = Some(pool);
    }

    // 步骤 7：劫持 fetch
    interceptor::hook_fetch();

    web_sys::console::log_1(
        &format!("ZFSG: 安全模块已激活 — 网关: {}", gateway_origin).into(),
    );
}

/// 重置会话（会话过期或网络错误时调用，重新进行挑战握手）
#[wasm_bindgen]
pub async fn reset_session() {
    let origin = gateway_origin()
        .expect("网关地址未设置")
        .to_string();

    // 清除当前会话
    unsafe {
        *SESSION.0.get() = None;
    }

    web_sys::console::warn_1(&"ZFSG: 正在重新建立安全通道...".into());

    // 重新进行挑战握手
    initialize(origin).await;
}

/// 获取当前会话 ID（调试用）
#[wasm_bindgen]
pub fn debug_session_id() -> String {
    unsafe { &*SESSION.0.get() }
        .as_ref()
        .map(|s| s.session_id.clone())
        .unwrap_or_default()
}

// ============================================================
// JS 互操作辅助函数
// ============================================================

/// POST JSON 到指定 URL（带自定义 header），返回解析后的 JsValue
async fn js_fetch_post_json_with_header(
    url: &str,
    body: &str,
    header_name: &str,
    header_value: &str,
) -> JsValue {
    use web_sys::{Request, RequestInit, RequestMode};

    let opts = RequestInit::new();
    opts.set_method("POST");
    opts.set_mode(RequestMode::Cors);

    if !body.is_empty() {
        opts.set_body(&JsValue::from_str(body));
    }

    let request = Request::new_with_str_and_init(url, &opts).expect("创建请求失败");
    let headers = request.headers();
    headers
        .set("Content-Type", "application/json")
        .expect("设置头失败");
    headers
        .set(header_name, header_value)
        .expect("设置自定义头失败");

    let win = web_sys::window().expect("无法获取 window");
    let resp_val = JsFuture::from(win.fetch_with_request(&request))
        .await
        .expect("fetch 失败");
    let resp: web_sys::Response = resp_val.dyn_into().expect("不是 Response");

    let json_val = JsFuture::from(resp.json().expect("json() 失败"))
        .await
        .expect("解析 JSON 失败");
    json_val
}

/// POST JSON 到指定 URL，返回解析后的 JsValue
async fn js_fetch_post_json(url: &str, body: &str) -> JsValue {
    use web_sys::{Request, RequestInit, RequestMode};

    let opts = RequestInit::new();
    opts.set_method("POST");
    opts.set_mode(RequestMode::Cors);

    if !body.is_empty() {
        opts.set_body(&JsValue::from_str(body));
    }

    let request = Request::new_with_str_and_init(url, &opts).expect("创建请求失败");
    request
        .headers()
        .set("Content-Type", "application/json")
        .expect("设置头失败");

    let win = web_sys::window().expect("无法获取 window");
    let resp_val = JsFuture::from(win.fetch_with_request(&request))
        .await
        .expect("fetch 失败");
    let resp: web_sys::Response = resp_val.dyn_into().expect("不是 Response");

    let json_val = JsFuture::from(resp.json().expect("json() 失败"))
        .await
        .expect("解析 JSON 失败");
    json_val
}

/// 从 JsValue (JSON 对象) 中获取字符串字段
fn js_json_get_string(obj: &JsValue, key: &str) -> String {
    use js_sys::Reflect;
    Reflect::get(obj, &JsValue::from_str(key))
        .expect("读取字段失败")
        .as_string()
        .expect("字段不是字符串")
}

/// Base64 编码（纯 Rust，无 eval 注入风险）
fn base64_encode(data: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(data)
}

/// Base64 解码（纯 Rust，无 eval 注入风险）
fn base64_decode(b64: &str) -> Vec<u8> {
    base64::engine::general_purpose::STANDARD
        .decode(b64)
        .expect("base64 解码失败")
}
