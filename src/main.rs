mod cache;
mod config;
mod error;
mod proxy;
mod routes;

use routes::AppState;
use tower_http::trace::TraceLayer;

#[tokio::main]
async fn main() {
    // 初始化日志
    tracing_subscriber::fmt().with_env_filter("info").init();

    let config = config::Config::from_env();
    let state = AppState::new(config.clone());

    // === 公开服务（端口 3000）===
    let public_app = routes::gateway::router()
        .layer(TraceLayer::new_for_http())
        .with_state(state.clone());

    let public_addr = format!("0.0.0.0:{}", config.public_port);
    let public_listener = tokio::net::TcpListener::bind(&public_addr)
        .await
        .unwrap_or_else(|e| {
            eprintln!("无法绑定公开端口 {}: {}", public_addr, e);
            std::process::exit(1);
        });

    // === 管理服务（端口 3001）===
    let admin_app = routes::admin::router()
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    let admin_addr = format!("127.0.0.1:{}", config.admin_port);
    let admin_listener = tokio::net::TcpListener::bind(&admin_addr)
        .await
        .unwrap_or_else(|e| {
            eprintln!("无法绑定管理端口 {}: {}", admin_addr, e);
            std::process::exit(1);
        });

    tracing::info!(
        "Rgateway 启动 — 公开端口: {}, 管理端口: {}, 后端: {}",
        config.public_port,
        config.admin_port,
        config.backend_url
    );

    // 同时运行两个服务
    let _ = tokio::join!(
        axum::serve(public_listener, public_app),
        axum::serve(admin_listener, admin_app),
    );
}
