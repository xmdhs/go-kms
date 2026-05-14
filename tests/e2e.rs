// End-to-end tests: spin up a Rust server on an ephemeral port, run the Rust
// client against it for V4/V5/V6, assert no errors.

use std::sync::Arc;
use std::time::Duration;

use kms_rs::client::{run, ClientConfig};
use kms_rs::kms::base::ServerConfig;
use kms_rs::server::KmsServer;
use tokio::net::TcpListener;

async fn spawn_server() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let mut cfg = ServerConfig::default();
    cfg.ip = "127.0.0.1".into();
    cfg.port = port;
    cfg.epid = "03612-00206-471-111111-03-1033-19041.0000-1232024".into();
    let cfg = Arc::new(cfg);
    let server = KmsServer::new_shared(cfg);
    tokio::spawn(async move {
        let _ = server.serve(listener).await;
    });
    // Brief yield to give the spawned task time to enter accept().
    tokio::time::sleep(Duration::from_millis(50)).await;
    port
}

async fn run_client_mode(mode: &str) {
    let port = spawn_server().await;
    let cfg = ClientConfig {
        ip: "127.0.0.1".into(),
        port,
        mode: mode.into(),
        ..Default::default()
    };
    run(&cfg).await.unwrap_or_else(|e| panic!("client failed: {}", e));
}

#[tokio::test]
async fn e2e_v4_office2010() {
    run_client_mode("Office2010").await;
}

#[tokio::test]
async fn e2e_v5_office2013() {
    run_client_mode("Office2013").await;
}

#[tokio::test]
async fn e2e_v6_windows10() {
    run_client_mode("Windows10").await;
}

#[tokio::test]
async fn e2e_v6_office2019() {
    run_client_mode("Office2019").await;
}
