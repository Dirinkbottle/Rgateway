use std::net::{IpAddr, SocketAddr};

use axum::{
    Json, Router,
    body::Bytes,
    extract::ConnectInfo,
    extract::State,
    http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Uri},
    response::{IntoResponse, Response},
    routing::post,
};
use serde::Deserialize;

use crate::cache::CachedResponse;

use super::AppState;

/// 公开网关路由（端口 3000）
pub fn router() -> Router<AppState> {
    Router::new()
        // 健康检查
        .route("/health", axum::routing::get(health))
        // Wasm 安全模块下发（从 ./wasm/pkg/ 读取）
        .route("/gateway/watchdogbody", axum::routing::get(wasm_bg))
        .route("/gateway/watchdogheader", axum::routing::get(wasm_header))
        .route("/gateway/watchdogglue", axum::routing::get(wasm_glue))
        // 挑战-响应握手
        .route("/gateway/challenge", post(challenge_handler))
        .route("/gateway/challenge/verify", post(challenge_verify_handler))
        // Wasm 加密中继入口
        .route(
            "/gateway/encrypted_relay",
            post(encrypted_relay_handler).options(cors_preflight),
        )
}

async fn health() -> &'static str {
    "ok"
}

/// CORS 预检（使用 CorsGuard 校验 Origin 白名单）
async fn cors_preflight(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let origin = headers
        .get("origin")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    match state.cors_guard.handle_preflight(origin) {
        Some((status, cors_headers)) => {
            let mut resp = status.into_response();
            for (name, value) in cors_headers {
                if let (Ok(n), Ok(v)) = (
                    HeaderName::from_bytes(name.as_bytes()),
                    HeaderValue::from_str(&value),
                ) {
                    resp.headers_mut().insert(n, v);
                }
            }
            resp
        }
        None => StatusCode::FORBIDDEN.into_response(),
    }
}

/// 下发 Wasm 二进制（使用 spawn_blocking 避免阻塞 tokio 工作线程）
async fn wasm_bg() -> Response {
    match tokio::task::spawn_blocking(|| std::fs::read("./wasm/pkg/openatomic_watchdog_bg.wasm")).await {
        Ok(Ok(bytes)) => {
            let mut resp = Response::new(axum::body::Body::from(bytes));
            let h = resp.headers_mut();
            h.insert(
                "content-type",
                HeaderValue::from_static("application/wasm"),
            );
            h.insert(
                "cache-control",
                HeaderValue::from_static("public, max-age=3600"),
            );
            h.insert(
                "access-control-allow-origin",
                HeaderValue::from_static("*"),
            );
            resp
        }
        _ => {
            tracing::warn!("openatomic_watchdog_bg.wasm 读取失败");
            (StatusCode::NOT_FOUND, "wasm not found").into_response()
        }
    }
}

/// 下发 Wasm JS 入口层（使用 spawn_blocking）
async fn wasm_glue() -> Response {
    match tokio::task::spawn_blocking(|| std::fs::read("./wasm/pkg/openatomic_watchdog.js")).await {
        Ok(Ok(bytes)) => {
            let mut resp = Response::new(axum::body::Body::from(bytes));
            let h = resp.headers_mut();
            h.insert(
                "content-type",
                HeaderValue::from_static("application/javascript"),
            );
            h.insert(
                "cache-control",
                HeaderValue::from_static("public, max-age=3600"),
            );
            h.insert(
                "access-control-allow-origin",
                HeaderValue::from_static("*"),
            );
            resp
        }
        _ => {
            tracing::warn!("openatomic_watchdog.js 读取失败");
            (StatusCode::NOT_FOUND, "js not found").into_response()
        }
    }
}

/// 下发 Wasm JS 胶水层（使用 spawn_blocking）
async fn wasm_header() -> Response {
    match tokio::task::spawn_blocking(|| std::fs::read("./wasm/pkg/openatomic_watchdog_bg.js")).await {
        Ok(Ok(bytes)) => {
            let mut resp = Response::new(axum::body::Body::from(bytes));
            let h = resp.headers_mut();
            h.insert(
                "content-type",
                HeaderValue::from_static("application/javascript"),
            );
            h.insert(
                "cache-control",
                HeaderValue::from_static("public, max-age=3600"),
            );
            h.insert(
                "access-control-allow-origin",
                HeaderValue::from_static("*"),
            );
            resp
        }
        _ => {
            tracing::warn!("openatomic_watchdog_bg.js 读取失败");
            (StatusCode::NOT_FOUND, "js not found").into_response()
        }
    }
}

// ============================================================
// CIDR 匹配
// ============================================================

/// 检查 IP 是否在 CIDR 范围内（支持 IPv4/IPv6）
fn ip_in_cidr(ip: IpAddr, cidr: &str) -> bool {
    let Some((net_str, prefix_len_str)) = cidr.split_once('/') else {
        // 没有前缀长度，视为单 IP 比较
        if let Ok(net) = cidr.parse::<IpAddr>() {
            return ip == net;
        }
        return false;
    };
    let Ok(prefix_len) = prefix_len_str.parse::<u8>() else {
        return false;
    };

    match (ip, net_str.parse::<IpAddr>()) {
        (IpAddr::V4(ipv4), Ok(IpAddr::V4(net))) => {
            if prefix_len > 32 {
                return false;
            }
            let mask = if prefix_len == 0 {
                0u32
            } else {
                !((1u32 << (32 - prefix_len)) - 1)
            };
            (u32::from(ipv4) & mask) == (u32::from(net) & mask)
        }
        (IpAddr::V6(ipv6), Ok(IpAddr::V6(net))) => {
            if prefix_len > 128 {
                return false;
            }
            let ip_u128 = u128::from(ipv6);
            let net_u128 = u128::from(net);
            let mask = if prefix_len == 0 {
                0u128
            } else {
                !((1u128 << (128 - prefix_len)) - 1)
            };
            (ip_u128 & mask) == (net_u128 & mask)
        }
        _ => false, // IPv4/IPv6 类型不匹配
    }
}

// ============================================================
// IP 提取（可信代理模式）
// ============================================================

/// 从请求头提取客户端 IP
///
/// 只有当 TCP 对端 IP 在可信代理列表中时，才信任 X-Forwarded-For / X-Real-IP。
/// 否则直接使用 TCP 连接的对端地址。
fn extract_client_ip(headers: &HeaderMap, peer_addr: IpAddr, trusted_proxies: &[String]) -> IpAddr {
    let is_trusted = trusted_proxies.iter().any(|cidr| ip_in_cidr(peer_addr, cidr));

    if is_trusted {
        // 优先 X-Forwarded-For（取第一个，即原始客户端 IP）
        if let Some(xff) = headers
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
        {
            if let Some(first) = xff.split(',').next() {
                if let Ok(ip) = first.trim().parse::<IpAddr>() {
                    return ip;
                }
            }
        }
        // 其次 X-Real-IP
        if let Some(xri) = headers
            .get("x-real-ip")
            .and_then(|v| v.to_str().ok())
        {
            if let Ok(ip) = xri.parse::<IpAddr>() {
                return ip;
            }
        }
    }

    peer_addr
}

// ============================================================
// 挑战-响应握手
// ============================================================

/// POST /gateway/challenge — 生成挑战（绑定客户端 IP）
async fn challenge_handler(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Response {
    let peer_addr = addr.ip();
    let trusted = &state.watchdog_config.network.trusted_proxies;
    let ip = extract_client_ip(&headers, peer_addr, trusted);

    match state.challenge_manager.create_challenge(ip) {
        Ok((challenge_id, challenge_bytes)) => Json(serde_json::json!({
            "challenge_id": challenge_id,
            "challenge": base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &challenge_bytes),
        }))
        .into_response(),
        Err(e) => {
            tracing::warn!("[challenge] 创建失败: {}, IP={}", e, ip);
            (StatusCode::TOO_MANY_REQUESTS, e).into_response()
        }
    }
}

#[derive(Deserialize)]
struct VerifyBody {
    challenge_id: String,
    response: String,
}

/// POST /gateway/challenge/verify — 验证挑战响应，签发临时密钥（校验 IP 绑定）
async fn challenge_verify_handler(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<VerifyBody>,
) -> Response {
    let peer_addr = addr.ip();
    let trusted = &state.watchdog_config.network.trusted_proxies;
    let ip = extract_client_ip(&headers, peer_addr, trusted);

    let response_bytes = match base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        &body.response,
    ) {
        Ok(b) => b,
        Err(_) => {
            return (StatusCode::BAD_REQUEST, "无效的 base64 编码").into_response();
        }
    };

    match state
        .challenge_manager
        .verify_and_create_session(&body.challenge_id, &response_bytes, ip)
    {
        Ok((session_id, ephemeral_key)) => Json(serde_json::json!({
            "session_id": session_id,
            "ephemeral_key": base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &ephemeral_key),
        }))
        .into_response(),
        Err(e) => {
            tracing::warn!("[challenge] 验证失败: {}", e);
            (StatusCode::UNAUTHORIZED, e).into_response()
        }
    }
}

// ============================================================
// Wasm 加密中继
// ============================================================

/// Wasm 加密中继处理入口
///
/// 安全校验链：
/// 1. IP 频率限制
/// 2. JA3 指纹校验 + Cookie 挑战
/// 3. AES-GCM 解密 + MAC 验证 + 滚动码校验
/// 4. SQL 注入 / XSS 检测
/// 5. 参数校验
/// 6. 转发到真实后端
async fn encrypted_relay_handler(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let peer_addr = addr.ip();
    let trusted = &state.watchdog_config.network.trusted_proxies;
    let ip = extract_client_ip(&headers, peer_addr, trusted);

    tracing::info!(
        "[encrypted_relay] incoming: ip={}, peer={}, body_len={}, ua={}",
        ip,
        peer_addr,
        body.len(),
        headers
            .get("user-agent")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("-")
    );

    // === 1. IP 频率限制 ===
    let (allowed, remaining) = state.rate_limiter.check(ip);
    tracing::info!(
        "[encrypted_relay] rate_limit: ip={}, allowed={}, remaining={}",
        ip,
        allowed,
        remaining
    );
    if !allowed {
        tracing::warn!("[encrypted_relay] rejected by rate_limit: ip={}", ip);
        return (StatusCode::TOO_MANY_REQUESTS, "请求过于频繁").into_response();
    }

    // === 2. JA3 指纹校验 + Cookie 挑战 ===
    let mut cookie_to_set: Option<String> = None;
    match state.ja3_filter.check(&headers, ip) {
        Ok(None) => {}
        Ok(Some(token)) => {
            cookie_to_set = Some(token);
        }
        Err(e) => {
            tracing::warn!("[encrypted_relay] rejected by ja3: err={:?}, ip={}", e, ip);
            return StatusCode::FORBIDDEN.into_response();
        }
    }

    // === 3. 解密 ===
    let decrypted = match state.decryptor.decrypt(ip, &body) {
        Ok(r) => {
            tracing::info!(
                "[encrypted_relay] decrypted: method={}, url={}, body_len={}, ip={}",
                r.method,
                r.url,
                r.body.len(),
                ip
            );
            r
        }
        Err(e) => {
            tracing::warn!("[encrypted_relay] decrypt failed: err={:?}, ip={}", e, ip);
            return StatusCode::FORBIDDEN.into_response();
        }
    };

    // === 4. SQL 注入 / XSS 检测 ===
    let ua = headers
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if let Some(reason) = state
        .inject_guard
        .inspect_request(&decrypted.url, "", "", ua)
    {
        tracing::warn!(
            "[encrypted_relay] rejected by injection: reason={}, ip={}",
            reason,
            ip
        );
        return StatusCode::FORBIDDEN.into_response();
    }

    // === 5. 参数校验 ===
    let method: Method = decrypted.method.parse().unwrap_or(Method::GET);
    // 提取路径：去掉 scheme://host 前缀，只保留 /path?query
    let url_path: String = if let Some(pos) = decrypted.url.find("://") {
        let after = &decrypted.url[pos + 3..];
        match after.split_once('/') {
            Some((_, rest)) => format!("/{}", rest),
            None => "/".to_string(),
        }
    } else {
        decrypted.url.clone()
    };
    let (path, query) = match url_path.split_once('?') {
        Some((p, q)) => (p, q),
        None => (url_path.as_str(), ""),
    };

    match state
        .param_validator
        .validate(&method, path, query, &headers, &decrypted.body)
    {
        crate::watchdog::params::ParamCheckResult::Ok => {}
        crate::watchdog::params::ParamCheckResult::NoRule => {
            tracing::warn!(
                "[encrypted_relay] rejected by rule: method={} path={} ip={}",
                method,
                path,
                ip
            );
            return StatusCode::FORBIDDEN.into_response();
        }
        crate::watchdog::params::ParamCheckResult::MethodNotAllowed => {
            tracing::warn!(
                "[encrypted_relay] rejected by method: method={} path={} ip={}",
                method,
                path,
                ip
            );
            return StatusCode::METHOD_NOT_ALLOWED.into_response();
        }
        crate::watchdog::params::ParamCheckResult::InvalidParam(msg) => {
            tracing::warn!("[encrypted_relay] rejected by params: msg={}, ip={}", msg, ip);
            return (StatusCode::BAD_REQUEST, msg).into_response();
        }
    }

    // === 6. 转发到真实后端 ===
    let (proxy_path, proxy_query) = match url_path.split_once('?') {
        Some((p, q)) => (p, Some(q)),
        None => (path, None),
    };

    match state
        .proxy
        .forward(&method, proxy_path, proxy_query, &headers, &decrypted.body)
        .await
    {
        Ok(r) => {
            let status = r.status;
            let resp_len = r.body.len();
            tracing::info!(
                "[encrypted_relay] proxy ok: method={} path={} status={} resp_len={} ip={}",
                method,
                proxy_path,
                status.as_u16(),
                resp_len,
                ip
            );
            let mut resp = proxy_to_response(r);
            resp.headers_mut().insert(
                HeaderName::from_static("x-zfsg"),
                HeaderValue::from_static("decrypted"),
            );
            // 设置 Cookie 挑战令牌
            if let Some(cookie) = cookie_to_set {
                if let Ok(val) = HeaderValue::from_str(&format!(
                    "zfsg_token={}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=86400",
                    cookie
                )) {
                    resp.headers_mut().insert("set-cookie", val);
                }
            }
            resp
        }
        Err(e) => {
            let err_summary = match &e {
                crate::error::AppError::BackendUnreachable(msg) => {
                    format!("BackendUnreachable: {}", msg)
                }
                crate::error::AppError::BackendError(code, msg) => {
                    format!("BackendError({}): {}", code.as_u16(), msg)
                }
                crate::error::AppError::ParamValidation(msg) => {
                    format!("ParamValidation: {}", msg)
                }
                crate::error::AppError::ChallengeFailed(msg) => {
                    format!("ChallengeFailed: {}", msg)
                }
                crate::error::AppError::InjectionDetected => "InjectionDetected".to_string(),
                crate::error::AppError::Forbidden => "Forbidden".to_string(),
                crate::error::AppError::RateLimited => "RateLimited".to_string(),
                crate::error::AppError::MethodNotAllowed => "MethodNotAllowed".to_string(),
                crate::error::AppError::DecryptionFailed(msg) => {
                    format!("DecryptionFailed: {}", msg)
                }
            };
            let resp = e.into_response();
            tracing::warn!(
                "[encrypted_relay] proxy err: method={} path={} status={} ip={} err={}",
                method,
                proxy_path,
                resp.status().as_u16(),
                ip,
                err_summary
            );
            resp
        }
    }
}

/// 核心网关处理：查缓存 → 转发后端 → 落缓存 → 返回
async fn gateway_handler(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let peer_addr = addr.ip();
    let trusted = &state.watchdog_config.network.trusted_proxies;
    let ip = extract_client_ip(&headers, peer_addr, trusted);
    tracing::info!("{} {} from {}", method, uri.path(), ip);

    // === CORS 预检（使用 CorsGuard 校验 Origin 白名单）===
    if method == Method::OPTIONS {
        let origin = headers
            .get("origin")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        return match state.cors_guard.handle_preflight(origin) {
            Some((status, cors_headers)) => {
                let mut resp = status.into_response();
                for (name, value) in cors_headers {
                    if let (Ok(n), Ok(v)) = (
                        HeaderName::from_bytes(name.as_bytes()),
                        HeaderValue::from_str(&value),
                    ) {
                        resp.headers_mut().insert(n, v);
                    }
                }
                resp
            }
            None => StatusCode::FORBIDDEN.into_response(),
        };
    }

    // === 注入检测 ===
    let ua = headers
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let query_str = uri.query().unwrap_or("");
    if let Some(reason) = state
        .inject_guard
        .inspect_request(uri.path(), query_str, "", ua)
    {
        tracing::warn!("注入检测: {}, IP={}", reason, ip);
        return StatusCode::FORBIDDEN.into_response();
    }

    // === 参数校验 ===
    match state
        .param_validator
        .validate(&method, uri.path(), query_str, &headers, &body)
    {
        crate::watchdog::params::ParamCheckResult::Ok => {}
        crate::watchdog::params::ParamCheckResult::NoRule => {
            return StatusCode::FORBIDDEN.into_response();
        }
        crate::watchdog::params::ParamCheckResult::MethodNotAllowed => {
            return StatusCode::METHOD_NOT_ALLOWED.into_response();
        }
        crate::watchdog::params::ParamCheckResult::InvalidParam(msg) => {
            return (StatusCode::BAD_REQUEST, msg).into_response();
        }
    }

    let cache_key = format!(
        "{}{}",
        uri.path(),
        uri.query().map(|q| format!("?{}", q)).unwrap_or_default()
    );

    let is_read = method == Method::GET || method == Method::HEAD;

    if is_read && let Some(cached) = state.cache.get(&cache_key).await {
        return hit(cached, &method, &headers, &state);
    }

    let proxy_method = if method == Method::HEAD {
        &Method::GET
    } else {
        &method
    };

    match state
        .proxy
        .forward(proxy_method, uri.path(), uri.query(), &headers, &body)
        .await
    {
        Ok(r) => {
            if method == Method::GET && !r.skip_cache {
                let cache_tag = r.cache_tag.clone();
                let cached = CachedResponse::new(
                    r.status,
                    r.headers.clone(),
                    r.body.clone(),
                    r.cache_ttl,
                    state.config.default_ttl,
                );
                state.cache.set(cache_key, cached, cache_tag).await;
            }

            miss(r, &method, &headers, &state)
        }
        Err(e) => {
            let mut resp = e.into_response();
            add_cors_headers_to_response(&mut resp, &headers, &state);
            resp
        }
    }
}

/// 缓存命中
fn hit(
    cached: CachedResponse,
    method: &Method,
    headers: &HeaderMap,
    state: &AppState,
) -> Response {
    let mut resp = cached_to_response(cached);
    if *method == Method::HEAD {
        *resp.body_mut() = axum::body::Body::empty();
    }
    resp.headers_mut().insert(
        HeaderName::from_static("x-cache"),
        HeaderValue::from_static("HIT"),
    );
    add_cors_headers_to_response(&mut resp, headers, state);
    resp
}

/// 缓存未命中
fn miss(
    r: crate::proxy::ProxyResponse,
    method: &Method,
    headers: &HeaderMap,
    state: &AppState,
) -> Response {
    let mut resp = proxy_to_response(r);
    if *method == Method::HEAD {
        *resp.body_mut() = axum::body::Body::empty();
    }
    resp.headers_mut().insert(
        HeaderName::from_static("x-cache"),
        HeaderValue::from_static("MISS"),
    );
    add_cors_headers_to_response(&mut resp, headers, state);
    resp
}

/// 为响应添加 CORS 头（使用 CorsGuard 校验 Origin 白名单）
fn add_cors_headers_to_response(resp: &mut Response, headers: &HeaderMap, state: &AppState) {
    let origin = headers
        .get("origin")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    for (name, value) in state.cors_guard.add_cors_headers(origin) {
        if let (Ok(n), Ok(v)) = (
            HeaderName::from_bytes(name.as_bytes()),
            HeaderValue::from_str(&value),
        ) {
            resp.headers_mut().insert(n, v);
        }
    }
}

/// 缓存条目 → axum Response
fn cached_to_response(cached: CachedResponse) -> Response {
    let mut resp = Response::new(cached.body.into());
    *resp.status_mut() = cached.status;
    for (name, value) in cached.headers {
        if let (Ok(n), Ok(v)) = (
            HeaderName::from_bytes(name.as_bytes()),
            HeaderValue::from_str(&value),
        ) {
            resp.headers_mut().insert(n, v);
        }
    }
    resp
}

/// 代理响应 → axum Response
fn proxy_to_response(r: crate::proxy::ProxyResponse) -> Response {
    let mut resp = Response::new(r.body.into());
    *resp.status_mut() = r.status;
    for (name, value) in r.headers {
        if let (Ok(n), Ok(v)) = (
            HeaderName::from_bytes(name.as_bytes()),
            HeaderValue::from_str(&value),
        ) {
            resp.headers_mut().insert(n, v);
        }
    }
    resp
}
