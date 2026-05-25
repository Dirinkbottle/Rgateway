//! fetch/XHR 劫持 + 时钟熔断
//!
//! 核心机制：
//! - 劫持 window.fetch，所有前端请求自动进入 Wasm 安全通道
//! - performance.now() 微秒级时钟检查，<50ms 间隔判定为自动化脚本
//! - 检测到异常时静默生成脏包，欺骗攻击者

use std::cell::UnsafeCell;

use js_sys::{Function, Object, Promise, Reflect};
use wasm_bindgen::prelude::*;
use web_sys::{console, window};

use crate::crypto::build_encrypted_request;

/// 上次请求的高精度时间戳（performance.now() 返回毫秒，含小数）
static mut LAST_REQUEST_TIME: f64 = 0.0;
/// 最小请求间隔阈值（毫秒），低于此值判定为自动化脚本
const MIN_DELTA_MS: f64 = 10.0;
/// 请求计数器（每次请求递增，服务端校验用）
static mut REQUEST_COUNTER: u64 = 0;

/// 原始 fetch 函数存储（模块内部，不暴露到 window）
struct FetchWrapper(UnsafeCell<Option<Function>>);
unsafe impl Sync for FetchWrapper {}
static ORIGINAL_FETCH: FetchWrapper = FetchWrapper(UnsafeCell::new(None));

/// 劫持 window.fetch，注入安全检查
///
/// 调用后，前端所有 fetch() 调用都会经过以下流程：
/// 1. 时钟熔断检查（<50ms → 脏包）
/// 2. 内存混淆 + 滚动码更新
/// 3. AES-GCM 全量加密
/// 4. 发送到 /gateway/encrypted_relay
pub fn hook_fetch() {
    let win = window().expect("无法获取 window 对象");

    // 保存原始 fetch 到模块内部静态变量（不暴露到 window）
    let original_fetch: Function = Reflect::get(&win, &"fetch".into())
        .expect("无法获取原始 fetch")
        .dyn_into::<Function>()
        .expect("原始 fetch 不是 Function");
    unsafe {
        *ORIGINAL_FETCH.0.get() = Some(original_fetch);
    }

    // 创建劫持闭包
    let closure = Closure::wrap(Box::new(move |url: JsValue, init: JsValue| -> Promise {
        // === 时钟熔断检查 ===
        let win = window().expect("无法获取 window");
        let perf = win.performance().expect("无法获取 Performance API");
        let now = perf.now();

        unsafe {
            let delta = now - LAST_REQUEST_TIME;
            if LAST_REQUEST_TIME > 0.0 && delta < MIN_DELTA_MS {
                // 检测到自动化爆破（for 循环等）
                console::warn_1(
                    &"ZFSG: 异常请求频率 (<50ms)，已触发防护机制".into(),
                );
                return generate_dirty_package();
            }
            LAST_REQUEST_TIME = now;
            REQUEST_COUNTER += 1;
        }

        // === 通过安全检查，走加密通道 ===
        let url_str = url.as_string().unwrap_or_default();
        let (method, body_bytes) = extract_request_info(&init);

        unsafe {
            let pool = crate::pool_mut();
            let session_id = crate::session_id();
            let counter = REQUEST_COUNTER;
            match build_encrypted_request(&url_str, &method, &body_bytes, pool, session_id, counter) {
                Ok((relay_url, packet)) => {
                    send_encrypted(&relay_url, &packet)
                }
                Err(e) => {
                    console::error_1(&format!("ZFSG 加密失败: {}", e).into());
                    generate_dirty_package()
                }
            }
        }
    }) as Box<dyn Fn(JsValue, JsValue) -> Promise>);

    // 替换全局 fetch
    Reflect::set(
        &win,
        &"fetch".into(),
        closure.as_ref().unchecked_ref(),
    )
    .expect("无法替换 fetch");

    // 防止闭包被 GC 回收
    closure.forget();
}

/// 从 RequestInit 中提取方法和 body
fn extract_request_info(init: &JsValue) -> (String, Vec<u8>) {
    let method = Reflect::get(init, &"method".into())
        .ok()
        .and_then(|v| v.as_string())
        .unwrap_or_else(|| "GET".to_string());

    let body = Reflect::get(init, &"body".into())
        .ok()
        .and_then(|v| {
            if v.is_null() || v.is_undefined() {
                None
            } else {
                // 尝试从字符串提取
                v.as_string()
                    .map(|s| s.into_bytes())
                    .or_else(|| {
                        // 尝试作为 Uint8Array 处理
                        let arr = js_sys::Uint8Array::new(&v);
                        Some(arr.to_vec())
                    })
            }
        })
        .unwrap_or_default();

    (method, body)
}

/// 用原始 fetch 发送加密包到网关
fn send_encrypted(url: &str, packet: &[u8]) -> Promise {
    let win = window().expect("无法获取 window");
    console::log_1(
        &format!(
            "[send] relay_url={}, packet_len={} bytes",
            url,
            packet.len()
        )
        .into(),
    );

    // 从模块静态变量获取原始 fetch
    let fetch_fn = unsafe {
        (*ORIGINAL_FETCH.0.get())
            .as_ref()
            .expect("原始 fetch 未初始化")
    };

    // 构建 RequestInit
    let init = Object::new();
    Reflect::set(&init, &"method".into(), &"POST".into()).unwrap();
    Reflect::set(&init, &"mode".into(), &"cors".into()).unwrap();

    // 设置请求体为 Uint8Array
    let body_array = js_sys::Uint8Array::from(packet);
    Reflect::set(&init, &"body".into(), &body_array).unwrap();

    // 设置 Content-Type
    let headers = Object::new();
    Reflect::set(
        &headers,
        &"Content-Type".into(),
        &"application/octet-stream".into(),
    )
    .unwrap();
    Reflect::set(&init, &"headers".into(), &headers).unwrap();

    let promise: Promise = fetch_fn
        .call2(&win, &url.into(), &init)
        .expect("调用原始 fetch 失败")
        .into();

    // 记录响应状态，检测会话过期（401/403）触发重新握手
    let on_resolve = Closure::wrap(Box::new(move |resp: JsValue| -> JsValue {
        let status = Reflect::get(&resp, &"status".into())
            .ok()
            .and_then(|v| v.as_f64());
        console::log_1(
            &format!("[send] encrypted response: status={:?}", status).into(),
        );
        // 会话过期或认证失败，触发重新挑战握手
        if let Some(s) = status {
            if s == 401.0 || s == 403.0 {
                console::warn_1(
                    &"ZFSG: 会话已过期，正在重新建立安全通道...".into(),
                );
                wasm_bindgen_futures::spawn_local(async {
                    crate::reset_session().await;
                });
            }
        }
        resp
    }) as Box<dyn FnMut(JsValue) -> JsValue>);

    let then_fn = Reflect::get(promise.as_ref(), &"then".into())
        .expect("Promise.then 不可用")
        .dyn_into::<Function>()
        .expect("Promise.then 不是函数");
    let observed: Promise = then_fn
        .call1(promise.as_ref(), on_resolve.as_ref())
        .expect("调用 Promise.then 失败")
        .into();
    on_resolve.forget();

    // 若网络/TCP 连接出错，重置会话并重新握手
    let on_reject = Closure::wrap(Box::new(move |_err: JsValue| -> JsValue {
        console::error_1(
            &format!("[send] encrypted request failed: {:?}", _err).into(),
        );
        wasm_bindgen_futures::spawn_local(async {
            crate::reset_session().await;
        });
        JsValue::UNDEFINED
    }) as Box<dyn FnMut(JsValue) -> JsValue>);

    let catch_fn = Reflect::get(observed.as_ref(), &"catch".into())
        .expect("Promise.catch 不可用")
        .dyn_into::<Function>()
        .expect("Promise.catch 不是函数");
    let chained: Promise = catch_fn
        .call1(observed.as_ref(), on_reject.as_ref())
        .expect("调用 Promise.catch 失败")
        .into();
    on_reject.forget();
    chained
}

/// 生成脏包：返回一个静默失败的 Promise
/// 用于欺骗自动化脚本，让其以为请求正常发出
fn generate_dirty_package() -> Promise {
    Promise::resolve(&JsValue::UNDEFINED)
}
