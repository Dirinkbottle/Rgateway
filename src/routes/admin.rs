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
}

/// 校验 Admin Bearer Token
///
/// 如果 ADMIN_TOKEN 环境变量为空，则跳过鉴权（仅限开发环境）。
/// 返回 Ok(()) 表示通过，Err(Response) 表示拒绝。
fn verify_admin_auth(headers: &HeaderMap, expected_token: &str) -> Result<(), Response> {
    if expected_token.is_empty() {
        return Ok(()); // 未配置 token，跳过鉴权
    }
    let auth = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let token = auth.strip_prefix("Bearer ").unwrap_or("");
    if token == expected_token {
        Ok(())
    } else {
        Err((
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "缺少或无效的 Admin Token"})),
        )
            .into_response())
    }
}

#[derive(Deserialize)]
struct InvalidateBody {
    tag: Option<String>,
    path: Option<String>,
}

/// GET /__gateway/stats
async fn stats(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(resp) = verify_admin_auth(&headers, &state.config.admin_token) {
        return resp;
    }
    Json(state.cache.stats()).into_response()
}

/// DELETE /__gateway/cache
async fn clear_cache(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(resp) = verify_admin_auth(&headers, &state.config.admin_token) {
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
    if let Err(resp) = verify_admin_auth(&headers, &state.config.admin_token) {
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
