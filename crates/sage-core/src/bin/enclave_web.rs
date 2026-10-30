use anyhow::Result;
use std::{future::IntoFuture, time::Duration};
use tokio::net::TcpListener;
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use sage_core::{
    config::Config, sage_agent::SageAgent, web_runtime, web_runtime::EnclaveWebConfig,
};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "sage=info,enclave_web=debug".into()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    dotenvy::dotenv().ok();

    let config = Config::from_env()?;
    let web_config = EnclaveWebConfig::from_env()?;
    let api_key = config
        .tinfoil_api_key
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("TINFOIL_API_KEY not set"))?;

    {
        use diesel::prelude::*;
        use diesel_migrations::{embed_migrations, EmbeddedMigrations, MigrationHarness};
        const MIGRATIONS: EmbeddedMigrations = embed_migrations!("migrations");
        let mut conn = diesel::PgConnection::establish(&config.database_url)?;
        conn.run_pending_migrations(MIGRATIONS)
            .map_err(|e| anyhow::anyhow!("Migration failed: {}", e))?;
    }

    SageAgent::configure_lm_with_temperature(
        &config.tinfoil_api_url,
        api_key,
        &config.tinfoil_model,
        0.1,
    )
    .await?;

    let app = web_runtime::build_router(config.clone(), web_config.clone())?;
    let listener = TcpListener::bind(("0.0.0.0", web_config.http_port)).await?;
    info!("enclave_web listening on 0.0.0.0:{}", web_config.http_port);
    serve_until_shutdown(listener, app, shutdown_signal(), Duration::from_secs(90)).await?;
    Ok(())
}

async fn shutdown_signal() {
    let interrupt = async {
        tokio::signal::ctrl_c()
            .await
            .expect("install SIGINT handler");
    };
    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("install SIGTERM handler")
            .recv()
            .await;
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        _ = interrupt => {},
        _ = terminate => {},
    }
}

async fn serve_until_shutdown(
    listener: TcpListener,
    app: axum::Router,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
    grace: Duration,
) -> Result<()> {
    let (started, draining) = tokio::sync::oneshot::channel();
    let mut server = Box::pin(
        axum::serve(listener, app)
            .with_graceful_shutdown(async move {
                shutdown.await;
                let _ = started.send(());
            })
            .into_future(),
    );
    tokio::select! {
        result = &mut server => result?,
        _ = draining => {
            info!("shutdown requested; draining active requests");
            tokio::time::timeout(grace, server)
                .await
                .map_err(|_| anyhow::anyhow!("request drain exceeded shutdown grace period"))??;
        }
    }
    Ok(())
}

#[cfg(test)]
mod shutdown_tests {
    use super::*;
    use std::sync::Arc;
    use tokio::sync::{oneshot, Notify};

    #[tokio::test]
    async fn idle_server_exits_when_shutdown_is_requested() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        serve_until_shutdown(
            listener,
            axum::Router::new(),
            async {},
            Duration::from_secs(1),
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn shutdown_drains_an_in_flight_request() {
        let entered = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        let app = axum::Router::new().route(
            "/",
            axum::routing::get({
                let entered = entered.clone();
                let release = release.clone();
                move || {
                    let entered = entered.clone();
                    let release = release.clone();
                    async move {
                        entered.notify_one();
                        release.notified().await;
                        "complete"
                    }
                }
            }),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/", listener.local_addr().unwrap());
        let (send, receive) = oneshot::channel();
        let mut server = tokio::spawn(serve_until_shutdown(
            listener,
            app,
            async {
                let _ = receive.await;
            },
            Duration::from_secs(1),
        ));
        let request =
            tokio::spawn(async move { reqwest::get(url).await.unwrap().text().await.unwrap() });
        entered.notified().await;
        send.send(()).unwrap();
        assert!(tokio::time::timeout(Duration::from_millis(20), &mut server)
            .await
            .is_err());
        release.notify_one();
        assert_eq!(request.await.unwrap(), "complete");
        tokio::time::timeout(Duration::from_secs(1), server)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn shutdown_bounds_a_stuck_request() {
        let entered = Arc::new(Notify::new());
        let app = axum::Router::new().route(
            "/",
            axum::routing::get({
                let entered = entered.clone();
                move || {
                    let entered = entered.clone();
                    async move {
                        entered.notify_one();
                        std::future::pending::<&'static str>().await
                    }
                }
            }),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/", listener.local_addr().unwrap());
        let (send, receive) = oneshot::channel();
        let server = tokio::spawn(serve_until_shutdown(
            listener,
            app,
            async {
                let _ = receive.await;
            },
            Duration::from_millis(20),
        ));
        let request = tokio::spawn(async move { reqwest::get(url).await });
        entered.notified().await;
        send.send(()).unwrap();
        let result = tokio::time::timeout(Duration::from_secs(1), server)
            .await
            .unwrap()
            .unwrap();
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("shutdown grace period"));
        request.abort();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn sigterm_exits_the_process_cleanly() {
        const FIXTURE: &str = "SAGE_SHUTDOWN_TEST_PORT_FILE";
        if let Ok(path) = std::env::var(FIXTURE) {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            std::fs::write(path, listener.local_addr().unwrap().port().to_string()).unwrap();
            let app = axum::Router::new().route("/", axum::routing::get(|| async { "ready" }));
            serve_until_shutdown(listener, app, shutdown_signal(), Duration::from_secs(1))
                .await
                .unwrap();
            return;
        }
        let path = std::env::temp_dir().join(format!("sage-shutdown-{}", uuid::Uuid::new_v4()));
        let mut child = tokio::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "shutdown_tests::sigterm_exits_the_process_cleanly",
            ])
            .env(FIXTURE, &path)
            .stdout(std::process::Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(1))
            .build()
            .unwrap();
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                if let Ok(port) = std::fs::read_to_string(&path) {
                    if let Ok(port) = port.parse::<u16>() {
                        if client
                            .get(format!("http://127.0.0.1:{port}/"))
                            .send()
                            .await
                            .is_ok()
                        {
                            break;
                        }
                    }
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        assert_eq!(
            unsafe { libc::kill(child.id().unwrap() as i32, libc::SIGTERM) },
            0
        );
        let status = tokio::time::timeout(Duration::from_secs(2), child.wait())
            .await
            .unwrap()
            .unwrap();
        let _ = std::fs::remove_file(path);
        assert!(
            status.success(),
            "SIGTERM must drain and return success: {status}"
        );
    }
}
