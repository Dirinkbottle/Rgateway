mod cache;
mod config;
mod error;
mod log_redact;
mod proxy;
mod routes;
mod watchdog;

use std::net::SocketAddr;

use routes::AppState;
use tower_http::trace::TraceLayer;

#[tokio::main(worker_threads = 2)]
async fn main() {
    // 初始化日志
    tracing_subscriber::fmt().with_env_filter("info").init();

    let config = config::Config::from_env();
    let state = AppState::new(config.clone());

    // === 公开服务（端口 3000）===
    let public_app = routes::gateway::router()
        .layer(TraceLayer::new_for_http())
        .with_state(state.clone())
        .into_make_service_with_connect_info::<SocketAddr>();

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
    tracing::info!(
        "Watchdog 安全模块已激活 — 配置: {}",
        config.watchdog_config_path
    );

    // 同时运行两个服务，支持优雅关闭（SIGINT/SIGTERM）
    let public_handle = tokio::spawn(
        axum::serve(public_listener, public_app)
            .with_graceful_shutdown(shutdown_signal())
            .into_future(),
    );
    let admin_handle = tokio::spawn(
        axum::serve(admin_listener, admin_app)
            .with_graceful_shutdown(shutdown_signal())
            .into_future(),
    );

    let _ = tokio::join!(public_handle, admin_handle);
    tracing::info!("Rgateway 已关闭");
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c().await.expect("无法监听 SIGINT");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("无法监听 SIGTERM")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => tracing::info!("收到 SIGINT，开始优雅关闭"),
        _ = terminate => tracing::info!("收到 SIGTERM，开始优雅关闭"),
    }
}
