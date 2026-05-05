use axum::http::{HeaderMap, Method, StatusCode};
use reqwest::Client;

use crate::error::AppError;
use std::time::Duration;

/// 代理响应（已剥离网关内部控制头）
pub struct ProxyResponse {
    pub status: StatusCode,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    /// 后端指定的缓存 TTL（X-Cache-TTL 头）
    pub cache_ttl: Option<Duration>,
    /// 缓存标签（X-Cache-Tag 头）
    pub cache_tag: Option<String>,
    /// 是否跳过缓存（X-Cache-Skip 头）
    pub skip_cache: bool,
}

/// reqwest 反向代理，将请求转发到 Go 后端
pub struct Proxy {
    client: Client,
    backend_url: String,
}

impl Proxy {
    pub fn new(backend_url: String) -> Self {
        Self {
            client: Client::new(),
            backend_url,
        }
    }

    /// 转发请求到后端，返回统一 ProxyResponse
    pub async fn forward(
        &self,
        method: &Method,
        path: &str,
        query: Option<&str>,
        headers: &HeaderMap,
        body: &[u8],
    ) -> Result<ProxyResponse, AppError> {
        let url = if let Some(q) = query {
            format!("{}{}?{}", self.backend_url, path, q)
        } else {
            format!("{}{}", self.backend_url, path)
        };

        // 构建 reqwest 请求，复制原始头（排除 host）
        let mut req = self.client.request(method.clone(), &url);
        for (name, value) in headers.iter() {
            if name.as_str().to_lowercase() != "host" {
                req = req.header(name.as_str(), value.as_bytes());
            }
        }

        if !body.is_empty() {
            req = req.body(body.to_vec());
        }

        let resp = req
            .send()
            .await
            .map_err(|e| AppError::BackendUnreachable(format!("后端不可达: {}", e)))?;

        let status = resp.status();

        // 提取网关控制头
        let cache_ttl = resp
            .headers()
            .get("x-cache-ttl")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok())
            .map(Duration::from_secs);

        let cache_tag = resp
            .headers()
            .get("x-cache-tag")
            .and_then(|v| v.to_str().ok())
            .map(String::from);

        let skip_cache = resp
            .headers()
            .get("x-cache-skip")
            .and_then(|v| v.to_str().ok())
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);

        // 收集响应头（排除网关控制头）
        let headers: Vec<(String, String)> = resp
            .headers()
            .iter()
            .filter(|(name, _)| {
                let n = name.as_str().to_lowercase();
                n != "x-cache-ttl" && n != "x-cache-tag" && n != "x-cache-skip"
            })
            .map(|(name, value)| (name.to_string(), value.to_str().unwrap_or("").to_string()))
            .collect();

        let body = resp
            .bytes()
            .await
            .map_err(|e| AppError::BackendError(status, format!("读取后端响应体失败: {}", e)))?;

        Ok(ProxyResponse {
            status,
            headers,
            body: body.to_vec(),
            cache_ttl,
            cache_tag,
            skip_cache,
        })
    }
}
