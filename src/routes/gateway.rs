use axum::{
    Router,
    body::Bytes,
    extract::State,
    http::{HeaderMap, HeaderName, HeaderValue, Method, Uri},
    response::{IntoResponse, Response},
    routing::any,
};

use crate::cache::CachedResponse;

use super::AppState;

/// 公开网关路由（端口 3000）
pub fn router() -> Router<AppState> {
    Router::new()
        // 健康检查
        .route("/health", axum::routing::get(health))
        // 代理所有 /api/* 请求
        .route("/api/{*path}", any(gateway_handler))
}

async fn health() -> &'static str {
    "ok"
}

/// 核心网关处理：查缓存 → 转发后端 → 落缓存 → 返回
async fn gateway_handler(
    State(state): State<AppState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let cache_key = format!(
        "{}{}",
        uri.path(),
        uri.query().map(|q| format!("?{}", q)).unwrap_or_default()
    );

    // get和head读缓存
    let is_read = method == Method::GET || method == Method::HEAD;

    // GET/HEAD 查缓存
    if is_read
        && let Some(cached) = state.cache.get(&cache_key).await {
            return hit(cached, &method);
        }

    // 转发到后端（HEAD 也用 GET 代理，以获取完整 body 用于缓存）
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
            // 仅 GET 落缓存（HEAD 不存只查，缓存已有 GET 的完整 body）
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

            miss(r, &method)
        }
        Err(e) => e.into_response(),
    }
}

/// 缓存命中
fn hit(cached: CachedResponse, method: &Method) -> Response {
    let mut resp = cached_to_response(cached);
    if *method == Method::HEAD {
        *resp.body_mut() = axum::body::Body::empty();
    }
    resp.headers_mut().insert(
        HeaderName::from_static("x-cache"),
        HeaderValue::from_static("HIT"),
    );
    resp
}

/// 缓存未命中
fn miss(r: crate::proxy::ProxyResponse, method: &Method) -> Response {
    let mut resp = proxy_to_response(r);
    if *method == Method::HEAD {
        *resp.body_mut() = axum::body::Body::empty();
    }
    resp.headers_mut().insert(
        HeaderName::from_static("x-cache"),
        HeaderValue::from_static("MISS"),
    );
    resp
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
