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
    /// 参数校验失败（400）
    ParamValidation(String),
    /// 挑战验证失败（401）
    ChallengeFailed(String),
    /// 注入攻击检测（403）
    InjectionDetected,
    /// 访问被拒绝（403）
    Forbidden,
    /// 请求频率超限（429）
    RateLimited,
    /// 方法不允许（405）
    MethodNotAllowed,
    /// 解密失败（400）
    DecryptionFailed(String),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, msg) = match self {
            AppError::BackendUnreachable(e) => (StatusCode::BAD_GATEWAY, e),
            AppError::BackendError(code, e) => (code, e),
            AppError::ParamValidation(e) => (StatusCode::BAD_REQUEST, e),
            AppError::ChallengeFailed(e) => (StatusCode::UNAUTHORIZED, e),
            AppError::InjectionDetected => (
                StatusCode::FORBIDDEN,
                "检测到异常请求，已拒绝".to_string(),
            ),
            AppError::Forbidden => (StatusCode::FORBIDDEN, "访问被拒绝".to_string()),
            AppError::RateLimited => (
                StatusCode::TOO_MANY_REQUESTS,
                "请求过于频繁，请稍后再试".to_string(),
            ),
            AppError::MethodNotAllowed => (StatusCode::METHOD_NOT_ALLOWED, "方法不允许".to_string()),
            AppError::DecryptionFailed(e) => (StatusCode::BAD_REQUEST, format!("解密失败: {}", e)),
        };
        let body = Json(serde_json::json!({ "error": msg }));
        (status, body).into_response()
    }
}
