// Tokio-based KMS client — mirrors reference/client/client.go.

use std::time::Duration;

use rand::Rng;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::crypto::kms_aes::{
    kms_decrypt_cbc, kms_encrypt_cbc, pkcs7_pad, pkcs7_unpad, random_salt,
};
use crate::crypto::v4_hash::v4_hash;
use crate::kms::base::{get_padding, KmsRequest, KmsResponse};
use crate::kms::filetime::{format_filetime, unix_to_filetime};
use crate::kms::utf16::{decode_utf16le, encode_utf16le};
use crate::kms::uuid::{must_uuid, KmsUuid};
use crate::rpc::{
    self, build_bind_request, build_rpc_request, recv_all, MsRpcHeader, MsRpcRequestHeader,
    PACKET_TYPE_BIND_ACK,
};

#[derive(Debug, Clone)]
pub struct ClientConfig {
    pub ip: String,
    pub port: u16,
    pub mode: String,
    pub cmid: String,
    pub machine: String,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            ip: "127.0.0.1".into(),
            port: 1688,
            mode: "Windows8.1".into(),
            cmid: String::new(),
            machine: String::new(),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ProductInfo {
    pub sku_id: &'static str,
    pub app_id: &'static str,
    pub kms_count_id: &'static str,
    pub proto_major: u16,
    pub proto_minor: u16,
    pub client_count: u32,
}

pub const PRODUCTS: &[(&str, ProductInfo)] = &[
    ("WindowsVista", ProductInfo {
        sku_id: "cfd8ff08-c0d7-452b-9f60-ef5c70c32094",
        app_id: "55c92734-d682-4d71-983e-d6ec3f16059f",
        kms_count_id: "212a64dc-43b1-4d3d-a30c-2fc69d2095c6",
        proto_major: 4, proto_minor: 0, client_count: 25,
    }),
    ("Windows7", ProductInfo {
        sku_id: "ae2ee509-1b34-41c0-acb7-6d4650168915",
        app_id: "55c92734-d682-4d71-983e-d6ec3f16059f",
        kms_count_id: "7fde5219-fbfa-484a-82c9-34d1ad53e856",
        proto_major: 4, proto_minor: 0, client_count: 25,
    }),
    ("Windows8", ProductInfo {
        sku_id: "458e1bec-837a-45f6-b9d5-925ed5d299de",
        app_id: "55c92734-d682-4d71-983e-d6ec3f16059f",
        kms_count_id: "3c40b358-5948-45af-923b-53d21fcc7e79",
        proto_major: 5, proto_minor: 0, client_count: 25,
    }),
    ("Windows8.1", ProductInfo {
        sku_id: "81671aaf-79d1-4eb1-b004-8cbbe173afea",
        app_id: "55c92734-d682-4d71-983e-d6ec3f16059f",
        kms_count_id: "cb8fc780-2c05-495a-9710-85afffc904d7",
        proto_major: 6, proto_minor: 0, client_count: 25,
    }),
    ("Windows10", ProductInfo {
        sku_id: "73111121-5571-4dd9-98a7-44d8780b9385",
        app_id: "55c92734-d682-4d71-983e-d6ec3f16059f",
        kms_count_id: "58e2134f-8e11-4d17-9cb2-91069c151148",
        proto_major: 6, proto_minor: 0, client_count: 25,
    }),
    ("Office2010", ProductInfo {
        sku_id: "6f327760-8c5c-417c-9b61-836a98287e0c",
        app_id: "59a52881-a989-479d-af46-f275c6370663",
        kms_count_id: "e85af946-2e25-47b7-83e1-bebcebeac611",
        proto_major: 4, proto_minor: 0, client_count: 5,
    }),
    ("Office2013", ProductInfo {
        sku_id: "b322da9c-a2e2-4058-9e4e-f59a6970bd69",
        app_id: "0ff1ce15-a989-479d-af46-f275c6370663",
        kms_count_id: "e6a6f1bf-9d40-40c3-aa9f-c77ba21578c0",
        proto_major: 5, proto_minor: 0, client_count: 5,
    }),
    ("Office2016", ProductInfo {
        sku_id: "d450596f-894d-49e0-966a-fd39ed4c4c64",
        app_id: "0ff1ce15-a989-479d-af46-f275c6370663",
        kms_count_id: "85b5f61b-320b-4be3-814a-b76b2bfafc82",
        proto_major: 6, proto_minor: 0, client_count: 5,
    }),
    ("Office2019", ProductInfo {
        sku_id: "0bc88885-718c-491d-921f-6f214349e79c",
        app_id: "0ff1ce15-a989-479d-af46-f275c6370663",
        kms_count_id: "617d9eb1-ef36-4f87-bbfb-481cbb3af187",
        proto_major: 6, proto_minor: 0, client_count: 5,
    }),
];

pub fn lookup_product(mode: &str) -> Option<ProductInfo> {
    PRODUCTS.iter().find(|(k, _)| *k == mode).map(|(_, v)| *v)
}

pub fn product_names() -> Vec<&'static str> {
    PRODUCTS.iter().map(|(k, _)| *k).collect()
}

#[derive(Debug)]
pub enum ClientError {
    UnknownMode(String),
    UnsupportedProto(u16),
    Io(std::io::Error),
    Rpc(rpc::RpcError),
    Other(String),
}

impl std::fmt::Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClientError::UnknownMode(m) => write!(f, "unknown product mode: {}", m),
            ClientError::UnsupportedProto(v) => write!(f, "unsupported protocol version: {}", v),
            ClientError::Io(e) => write!(f, "io: {}", e),
            ClientError::Rpc(e) => write!(f, "rpc: {}", e),
            ClientError::Other(s) => f.write_str(s),
        }
    }
}
impl std::error::Error for ClientError {}
impl From<std::io::Error> for ClientError {
    fn from(e: std::io::Error) -> Self {
        ClientError::Io(e)
    }
}
impl From<rpc::RpcError> for ClientError {
    fn from(e: rpc::RpcError) -> Self {
        ClientError::Rpc(e)
    }
}
impl From<crate::crypto::kms_aes::CryptoError> for ClientError {
    fn from(e: crate::crypto::kms_aes::CryptoError) -> Self {
        ClientError::Other(e.to_string())
    }
}
impl From<crate::kms::base::KmsError> for ClientError {
    fn from(e: crate::kms::base::KmsError) -> Self {
        ClientError::Other(e.to_string())
    }
}

pub async fn run(config: &ClientConfig) -> Result<(), ClientError> {
    let product = lookup_product(&config.mode)
        .ok_or_else(|| ClientError::UnknownMode(config.mode.clone()))?;

    let cmid = if config.cmid.is_empty() {
        KmsUuid::random().to_string()
    } else {
        config.cmid.clone()
    };
    let machine = if config.machine.is_empty() {
        random_machine_name()
    } else {
        config.machine.clone()
    };

    println!("Connecting to KMS server: {}:{}", config.ip, config.port);
    let mut stream = timeout(
        Duration::from_secs(10),
        TcpStream::connect((config.ip.as_str(), config.port)),
    )
    .await
    .map_err(|_| ClientError::Other("connect timeout".into()))??;
    println!("Connection successful");

    // RPC BIND
    let bind_req = build_bind_request(1);
    stream.write_all(&bind_req).await?;
    let bind_ack = recv_all(&mut stream, 512).await?;
    let bind_ack_header = MsRpcHeader::parse(&bind_ack)?;
    if bind_ack_header.typ != PACKET_TYPE_BIND_ACK {
        return Err(ClientError::Other(format!(
            "expected bind ack, got type 0x{:02x}",
            bind_ack_header.typ
        )));
    }
    println!("RPC bind acknowledged");

    let kms_request_data = build_kms_request_data(&product, &cmid, &machine);
    let enveloped: Vec<u8> = match product.proto_major {
        4 => build_v4_client_request(&kms_request_data),
        5 => build_v5_v6_client_request(&kms_request_data, product.proto_minor, product.proto_major, false)?,
        6 => build_v5_v6_client_request(&kms_request_data, product.proto_minor, product.proto_major, true)?,
        v => return Err(ClientError::UnsupportedProto(v)),
    };

    let rpc_req = build_rpc_request(&enveloped, 2);
    stream.write_all(&rpc_req).await?;

    let resp_data = recv_all(&mut stream, 512).await?;
    let resp_header = MsRpcRequestHeader::parse(&resp_data)?;
    let pdu = resp_header
        .pdu_data(&resp_data)
        .ok_or_else(|| ClientError::Other("failed to extract response PDU data".into()))?
        .to_vec();

    match product.proto_major {
        4 => parse_v4_response(&pdu)?,
        5 => parse_v5_v6_response(&pdu, false)?,
        6 => parse_v5_v6_response(&pdu, true)?,
        v => return Err(ClientError::UnsupportedProto(v)),
    }
    Ok(())
}

pub fn build_kms_request_data(product: &ProductInfo, cmid: &str, machine: &str) -> Vec<u8> {
    let sku = must_uuid(product.sku_id);
    let app = must_uuid(product.app_id);
    let kms_id = must_uuid(product.kms_count_id);
    let cm = must_uuid(cmid);
    let mut padded_machine = vec![0u8; 128];
    let m = encode_utf16le(machine);
    let copy_len = m.len().min(128);
    padded_machine[..copy_len].copy_from_slice(&m[..copy_len]);

    let now = current_unix_secs();
    let request_time = unix_to_filetime(now, 0);

    let req = KmsRequest {
        version_minor: product.proto_minor,
        version_major: product.proto_major,
        is_client_vm: 0,
        license_status: 2,
        grace_time: 43200 * 2,
        application_id: app,
        sku_id: sku,
        kms_counted_id: kms_id,
        client_machine_id: cm,
        required_client_count: product.client_count,
        request_time: request_time as u64,
        previous_client_machine_id: KmsUuid::default(),
        machine_name_raw: padded_machine,
    };
    req.marshal()
}

pub fn build_v4_client_request(kms_data: &[u8]) -> Vec<u8> {
    let hash = v4_hash(kms_data);
    let body_length = (kms_data.len() + 16) as u32;
    let padding = vec![0u8; get_padding(body_length as usize)];
    let mut out = Vec::with_capacity(8 + kms_data.len() + 16 + padding.len());
    out.extend_from_slice(&body_length.to_le_bytes());
    out.extend_from_slice(&body_length.to_le_bytes());
    out.extend_from_slice(kms_data);
    out.extend_from_slice(&hash);
    out.extend_from_slice(&padding);
    out
}

pub fn build_v5_v6_client_request(
    kms_data: &[u8],
    version_minor: u16,
    version_major: u16,
    is_v6: bool,
) -> Result<Vec<u8>, ClientError> {
    let esalt = random_salt();
    let dsalt = kms_decrypt_cbc(&esalt, &esalt, is_v6)?;

    let mut decrypted = Vec::with_capacity(16 + kms_data.len());
    decrypted.extend_from_slice(&dsalt[..16]);
    decrypted.extend_from_slice(kms_data);

    let padded = pkcs7_pad(&decrypted, 16);
    let encrypted = kms_encrypt_cbc(&padded, &esalt, is_v6)?;

    let body_length = (2 + 2 + encrypted.len()) as u32;
    let mut out = Vec::with_capacity(8 + 4 + encrypted.len());
    out.extend_from_slice(&body_length.to_le_bytes());
    out.extend_from_slice(&body_length.to_le_bytes());
    out.extend_from_slice(&version_minor.to_le_bytes());
    out.extend_from_slice(&version_major.to_le_bytes());
    out.extend_from_slice(&encrypted);
    Ok(out)
}

pub fn parse_v4_response(data: &[u8]) -> Result<(), ClientError> {
    if data.len() < 12 {
        return Err(ClientError::Other("V4 response too short".into()));
    }
    let body_length2 = u32::from_le_bytes([data[8], data[9], data[10], data[11]]) as usize;
    let remaining = &data[12..];
    if body_length2 < 16 || body_length2 > remaining.len() {
        return Err(ClientError::Other("V4 response body too short".into()));
    }
    let response_data = &remaining[..body_length2 - 16];
    let resp = KmsResponse::parse(response_data)?;
    print_response(&resp);
    Ok(())
}

pub fn parse_v5_v6_response(data: &[u8], is_v6: bool) -> Result<(), ClientError> {
    if data.len() < 16 {
        return Err(ClientError::Other("V5/V6 response too short".into()));
    }
    let body_length1 = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;
    let remaining = &data[16..];
    if remaining.len() < 16 {
        return Err(ClientError::Other("V5/V6 response missing salt".into()));
    }
    let salt = &remaining[..16];
    let padding_len = get_padding(body_length1);
    let encrypted_end = remaining.len() - padding_len;
    if encrypted_end <= 16 {
        return Err(ClientError::Other("V5/V6 encrypted too short".into()));
    }
    let encrypted = &remaining[16..encrypted_end];
    let decrypted = kms_decrypt_cbc(encrypted, salt, is_v6)?;
    let decrypted = pkcs7_unpad(&decrypted)?;
    let resp = KmsResponse::parse(&decrypted)?;
    print_response(&resp);
    if is_v6 {
        let resp_len = 44 + resp.epid_len as usize;
        let hwid_offset = resp_len + 16 + 32;
        if decrypted.len() >= hwid_offset + 8 {
            let hwid = &decrypted[hwid_offset..hwid_offset + 8];
            let mut s = String::with_capacity(16);
            for &b in hwid {
                s.push_str(&format!("{:02x}", b));
            }
            println!("HWID: {}", s);
        }
    }
    Ok(())
}

fn print_response(resp: &KmsResponse) {
    let epid = decode_utf16le(&resp.kms_epid);
    println!("=== KMS Response ===");
    println!("  ePID: {}", epid);
    println!("  Client Machine ID: {}", resp.client_machine_id);
    println!("  Response Time: {}", format_filetime(resp.response_time as i64));
    println!("  Current Client Count: {}", resp.current_client_count);
    println!("  VL Activation Interval: {} minutes", resp.vl_activation_interval);
    println!("  VL Renewal Interval: {} minutes", resp.vl_renewal_interval);
}

pub fn random_machine_name() -> String {
    const CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    let mut rng = rand::thread_rng();
    let len = 8 + rng.gen_range(0..8);
    let mut s = String::with_capacity(len);
    for _ in 0..len {
        s.push(CHARS[rng.gen_range(0..CHARS.len())] as char);
    }
    s.to_uppercase()
}

fn current_unix_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
