use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};

/// 网关统一错误类型
pub enum AppError {
    /// 后端不可达
    BackendUnreachable(String),
    /// 后端返回错误
    BackendError(StatusCode, String),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, msg) = match self {
            AppError::BackendUnreachable(e) => (StatusCode::BAD_GATEWAY, e),
            AppError::BackendError(code, e) => (code, e),
        };
        let body = Json(serde_json::json!({ "error": msg }));
        (status, body).into_response()
    }
}
