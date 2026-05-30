use axum::{
    Json, Router,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{delete, get, post},
};
use serde::Deserialize;

use super::AppState;

/// 管理 API 路由（端口 3001）
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/__gateway/stats", get(stats))
        .route("/__gateway/cache", delete(clear_cache))
        .route("/__gateway/invalidate", post(invalidate))
        // 管理面板静态文件
        .route("/admin", get(admin_panel))
        .route("/", get(admin_panel))
}

/// 校验 Admin Bearer Token（常量时间比较，防时序攻击）
///
/// - ADMIN_TOKEN 为空 + DEV_ALLOW_INSECURE_ADMIN=true → 放行（仅开发环境）
/// - ADMIN_TOKEN 为空 + DEV_ALLOW_INSECURE_ADMIN=false → 拒绝并告警
/// - ADMIN_TOKEN 非空 → 常量时间比较
#[allow(clippy::result_large_err)]
fn verify_admin_auth(
    headers: &HeaderMap,
    expected_token: &str,
    dev_allow_insecure: bool,
    client_ip: &str,
) -> Result<(), Response> {
    if expected_token.is_empty() {
        if dev_allow_insecure {
            tracing::warn!(
                "[admin] 无鉴权放行（DEV_ALLOW_INSECURE_ADMIN=true），IP={}",
                client_ip
            );
            return Ok(());
        } else {
            tracing::warn!(
                "[admin] ADMIN_TOKEN 未配置且未启用 DEV_ALLOW_INSECURE_ADMIN，拒绝访问，IP={}",
                client_ip
            );
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "管理接口未配置鉴权"})),
            )
                .into_response());
        }
    }

    let auth = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let token = auth.strip_prefix("Bearer ").unwrap_or("");

    // 常量时间比较，防时序攻击
    use subtle::ConstantTimeEq;
    if token.len() == expected_token.len() {
        let eq: bool = token.as_bytes().ct_eq(expected_token.as_bytes()).into();
        if eq {
            return Ok(());
        }
    }

    tracing::warn!("[admin] 鉴权失败，IP={}", client_ip);
    Err((
        StatusCode::UNAUTHORIZED,
        Json(serde_json::json!({"error": "缺少或无效的 Admin Token"})),
    )
        .into_response())
}

#[derive(Deserialize)]
struct InvalidateBody {
    tag: Option<String>,
    path: Option<String>,
}

/// GET / 或 /admin — 管理面板
async fn admin_panel() -> Response {
    match tokio::task::spawn_blocking(|| std::fs::read_to_string("./frontend/admin/index.html"))
        .await
    {
        Ok(Ok(html)) => (
            [(axum::http::header::CONTENT_TYPE, "text/html; charset=utf-8")],
            html,
        )
            .into_response(),
        _ => (StatusCode::NOT_FOUND, "管理面板未找到").into_response(),
    }
}

/// GET /__gateway/stats
async fn stats(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(resp) = verify_admin_auth(
        &headers,
        &state.config.admin_token,
        state.config.dev_allow_insecure_admin,
        "admin-port",
    ) {
        return resp;
    }
    Json(state.cache.stats()).into_response()
}

/// DELETE /__gateway/cache
async fn clear_cache(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(resp) = verify_admin_auth(
        &headers,
        &state.config.admin_token,
        state.config.dev_allow_insecure_admin,
        "admin-port",
    ) {
        return resp;
    }
    state.cache.clear().await;
    StatusCode::NO_CONTENT.into_response()
}

/// POST /__gateway/invalidate  {"tag":"..."} 或 {"path":"..."}
async fn invalidate(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<InvalidateBody>,
) -> Response {
    if let Err(resp) = verify_admin_auth(
        &headers,
        &state.config.admin_token,
        state.config.dev_allow_insecure_admin,
        "admin-port",
    ) {
        return resp;
    }
    match (body.tag, body.path) {
        (Some(tag), _) => {
            state.cache.invalidate_by_tag(&tag).await;
            StatusCode::NO_CONTENT.into_response()
        }
        (_, Some(path)) => {
            state.cache.invalidate_by_path(&path).await;
            StatusCode::NO_CONTENT.into_response()
        }
        _ => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "需要 tag 或 path 字段"})),
        )
            .into_response(),
    }
}
