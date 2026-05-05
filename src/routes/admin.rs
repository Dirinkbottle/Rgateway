use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{delete, get, post},
    Json, Router,
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

#[derive(Deserialize)]
struct InvalidateBody {
    tag: Option<String>,
    path: Option<String>,
}

/// GET /__gateway/stats
async fn stats(State(state): State<AppState>) -> impl IntoResponse {
    Json(state.cache.stats())
}

/// DELETE /__gateway/cache
async fn clear_cache(State(state): State<AppState>) -> impl IntoResponse {
    state.cache.clear().await;
    StatusCode::NO_CONTENT
}

/// POST /__gateway/invalidate  {"tag":"..."} 或 {"path":"..."}
async fn invalidate(
    State(state): State<AppState>,
    Json(body): Json<InvalidateBody>,
) -> Response {
    match (body.tag, body.path) {
        (Some(tag), _) => {
            state.cache.invalidate_by_tag(&tag).await;
            StatusCode::NO_CONTENT.into_response()
        }
        (_, Some(path)) => {
            state.cache.invalidate_by_path(&path).await;
            StatusCode::NO_CONTENT.into_response()
        }
        _ => (StatusCode::BAD_REQUEST,
              Json(serde_json::json!({"error": "需要 tag 或 path 字段"}))).into_response(),
    }
}
