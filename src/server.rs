// Tokio-based KMS server — mirrors reference/server/server.go semantics.

use std::sync::Arc;
use std::time::Duration;

use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

use crate::kms::base::ServerConfig;
use crate::kms::versions::generate_kms_response_data;
use crate::logger;
use crate::rpc::{
    self, build_bind_ack_response, build_msrpc_response, recv_all_into, MsRpcHeader,
    MsRpcRequestHeader, PACKET_TYPE_BIND, PACKET_TYPE_REQUEST,
};

pub const MAX_FRAG_LEN: u16 = 512;
pub const CONN_TIMEOUT: Duration = Duration::from_secs(10);

pub struct KmsServer {
    pub config: Arc<ServerConfig>,
}

impl KmsServer {
    pub fn new(config: ServerConfig) -> Self {
        Self {
            config: Arc::new(config),
        }
    }

    pub fn new_shared(config: Arc<ServerConfig>) -> Self {
        Self { config }
    }

    pub async fn listen_and_serve(&self) -> std::io::Result<()> {
        let addr = format!("{}:{}", self.config.ip, self.config.port);
        let listener = TcpListener::bind(&addr).await?;
        logger::info(&format!("KMS Server listening on {}", addr));
        logger::info(&format!("HWID: {}", hex_lower(&self.config.hwid)));
        self.serve(listener).await
    }

    /// Serve on an already-bound listener. Useful for tests where the port is
    /// chosen by the kernel.
    pub async fn serve(&self, listener: TcpListener) -> std::io::Result<()> {
        loop {
            match listener.accept().await {
                Ok((stream, _peer)) => {
                    let cfg = self.config.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handle_connection(stream, cfg).await {
                            logger::warn(&format!("connection error: {}", e));
                        }
                    });
                }
                Err(e) => logger::warn(&format!("accept failed: {}", e)),
            }
        }
    }
}

pub async fn handle_connection(
    mut stream: TcpStream,
    config: Arc<ServerConfig>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let remote = stream
        .peer_addr()
        .map(|a| a.to_string())
        .unwrap_or_else(|_| "<unknown>".into());
    logger::info(&format!("Connection accepted from {}", remote));

    let mut buf = vec![0u8; MAX_FRAG_LEN as usize];

    loop {
        let read_res = timeout(CONN_TIMEOUT, recv_all_into(&mut stream, &mut buf, MAX_FRAG_LEN)).await;
        let n = match read_res {
            Ok(Ok(n)) => n,
            Ok(Err(rpc::RpcError::Io(e))) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Ok(Err(e)) => {
                logger::warn(&format!("recv: {}", e));
                break;
            }
            Err(_) => {
                logger::warn("read timeout");
                break;
            }
        };
        if n == 0 {
            break;
        }
        let data = &buf[..n];
        let header = match MsRpcHeader::parse(data) {
            Ok(h) => h,
            Err(e) => {
                logger::warn(&format!("bad RPC header: {}", e));
                break;
            }
        };

        let response: Option<Vec<u8>> = match header.typ {
            PACKET_TYPE_BIND => match build_bind_ack_response(data, config.port, header.call_id) {
                Ok(r) => Some(r),
                Err(e) => {
                    logger::error(&format!("bind ack: {}", e));
                    None
                }
            },
            PACKET_TYPE_REQUEST => match MsRpcRequestHeader::parse(data) {
                Ok(req_header) => match req_header.pdu_data(data) {
                    Some(pdu) => match generate_kms_response_data(pdu, &config) {
                        Ok(kms_resp) => Some(build_msrpc_response(&req_header, &kms_resp)),
                        Err(e) => {
                            logger::error(&format!("kms response: {}", e));
                            None
                        }
                    },
                    None => {
                        logger::error("failed to extract PDU data");
                        None
                    }
                },
                Err(e) => {
                    logger::error(&format!("bad request header: {}", e));
                    None
                }
            },
            other => {
                logger::warn(&format!("unknown RPC packet type 0x{:02x}", other));
                None
            }
        };

        let response = match response {
            Some(r) => r,
            None => break,
        };
        if timeout(CONN_TIMEOUT, stream.write_all(&response)).await.is_err() {
            logger::warn("write timeout");
            break;
        }
        if header.typ == PACKET_TYPE_REQUEST {
            break;
        }
    }
    logger::info(&format!("Connection closed: {}", remote));
    Ok(())
}

fn hex_lower(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for &v in b {
        s.push_str(&format!("{:02x}", v));
    }
    s
}
