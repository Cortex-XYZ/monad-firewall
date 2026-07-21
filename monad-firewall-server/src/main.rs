use std::net::SocketAddr;
use std::sync::Arc;

use monad_firewall_server::{app, MockFirewallState, SharedState};
use tokio::net::TcpListener;
use tracing_subscriber::EnvFilter;


#[expect(
    clippy::unnecessary_wraps,
    reason = "constructing the aya backend will be fallible"
)]
fn build_state() -> anyhow::Result<SharedState> {
    Ok(Arc::new(MockFirewallState::seeded()))
}


async fn shutdown_signal() {
    let ctrl_c = async {
        match tokio::signal::ctrl_c().await {
            Ok(()) => {}
            Err(err) => {
                tracing::error!("failed to install Ctrl-C handler: {err}");
                // A failed install must not itself trigger shutdown; let the other signal govern.
                std::future::pending::<()>().await;
            }
        }
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut stream) => {
                stream.recv().await;
            }
            Err(err) => {
                tracing::error!("failed to install SIGTERM handler: {err}");
                std::future::pending::<()>().await;
            }
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {},
        () = terminate => {},
    }

    tracing::info!("shutdown signal received, draining connections");
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let state = build_state()?;

    let addr: SocketAddr = std::env::var("MONAD_FW_SERVER_ADDR")
        .unwrap_or_else(|_| "0.0.0.0:8787".to_string())
        .parse()?;

    let listener = TcpListener::bind(addr).await?;
    tracing::info!("monad-firewall-server listening on http://{addr}");

    axum::serve(listener, app(state))
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    Ok(())
}
