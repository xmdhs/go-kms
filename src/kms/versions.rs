// KMS V4 / V5 / V6 protocol-version handlers — matches reference/kms/versions.go.

use sha2::{Digest, Sha256};

use crate::crypto::kms_aes::{
    kms_decrypt_cbc, kms_encrypt_cbc, pkcs7_pad, pkcs7_unpad, random_salt, CryptoError,
};
use crate::crypto::v4_hash::v4_hash;
use crate::crypto::v6_mac::{v6_hmac_parts, v6_mac_key};

use super::base::{
    get_padding, server_logic, GenericRequestHeader, KmsError, KmsRequest, KmsResponse,
    ServerConfig,
};

#[derive(Debug)]
pub enum VersionError {
    Kms(KmsError),
    Crypto(CryptoError),
    Other(String),
}

impl std::fmt::Display for VersionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VersionError::Kms(e) => write!(f, "{}", e),
            VersionError::Crypto(e) => write!(f, "{}", e),
            VersionError::Other(s) => f.write_str(s),
        }
    }
}
impl std::error::Error for VersionError {}
impl From<KmsError> for VersionError {
    fn from(e: KmsError) -> Self {
        VersionError::Kms(e)
    }
}
impl From<CryptoError> for VersionError {
    fn from(e: CryptoError) -> Self {
        VersionError::Crypto(e)
    }
}

/// Dispatches to the appropriate version handler based on `header.VersionMajor`.
pub fn generate_kms_response_data(
    data: &[u8],
    config: &ServerConfig,
) -> Result<Vec<u8>, VersionError> {
    let header = GenericRequestHeader::parse(data)?;
    match header.version_major {
        4 => handle_v4_request(data, config),
        5 => handle_v5_request(data, &header, config),
        6 => handle_v6_request(data, &header, config),
        _ => Ok(handle_unknown_request()),
    }
}

pub fn handle_unknown_request() -> Vec<u8> {
    let mut resp = vec![0u8; 12];
    // SL_E_VL_KEY_MANAGEMENT_SERVICE_ID_MISMATCH = 0xC004F042
    resp[8..12].copy_from_slice(&0xC004F042u32.to_le_bytes());
    resp
}

// ---------- V4 ----------

pub fn handle_v4_request(data: &[u8], config: &ServerConfig) -> Result<Vec<u8>, VersionError> {
    if data.len() < 8 {
        return Err(VersionError::Other("V4 request too short".into()));
    }
    let body_length1 = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;
    let remaining = &data[8..];
    if body_length1 < 16 {
        return Err(VersionError::Other(format!(
            "V4 body length too short: {}",
            body_length1
        )));
    }
    if body_length1 > remaining.len() {
        return Err(VersionError::Other("V4 body length mismatch".into()));
    }
    let request_data = &remaining[..body_length1 - 16];
    let kms_request = KmsRequest::parse(request_data)?;
    let response = server_logic(&kms_request, config);
    let response_bytes = response.marshal();
    let the_hash = v4_hash(&response_bytes);

    let body_length = (response_bytes.len() + 16) as u32;
    let padding = vec![0u8; get_padding(body_length as usize)];

    let mut resp = Vec::with_capacity(4 + 4 + 4 + response_bytes.len() + 16 + padding.len());
    resp.extend_from_slice(&body_length.to_le_bytes());
    resp.extend_from_slice(&0x00000200u32.to_be_bytes());
    resp.extend_from_slice(&body_length.to_le_bytes());
    resp.extend_from_slice(&response_bytes);
    resp.extend_from_slice(&the_hash);
    resp.extend_from_slice(&padding);
    Ok(resp)
}

// ---------- V5 ----------

pub fn handle_v5_request(
    data: &[u8],
    header: &GenericRequestHeader,
    config: &ServerConfig,
) -> Result<Vec<u8>, VersionError> {
    handle_v5_v6_request(data, header, config, false)
}

// ---------- V6 ----------

pub fn handle_v6_request(
    data: &[u8],
    header: &GenericRequestHeader,
    config: &ServerConfig,
) -> Result<Vec<u8>, VersionError> {
    handle_v5_v6_request(data, header, config, true)
}

fn handle_v5_v6_request(
    data: &[u8],
    header: &GenericRequestHeader,
    config: &ServerConfig,
    is_v6: bool,
) -> Result<Vec<u8>, VersionError> {
    const OFFSET: usize = 12;
    let body_length1 = header.body_length1 as usize;
    let version_minor = header.version_minor;
    let version_major = header.version_major;

    let message_data = &data[OFFSET..];
    let ciphertext_len = body_length1.saturating_sub(4);
    if message_data.len() < ciphertext_len || ciphertext_len < 16 {
        return Err(VersionError::Other(format!(
            "V5/V6 message too short: {} (need {})",
            message_data.len(),
            ciphertext_len
        )));
    }

    let salt = &message_data[..16];

    let decrypted = kms_decrypt_cbc(&message_data[..ciphertext_len], salt, is_v6)?;
    let decrypted = pkcs7_unpad(&decrypted)?;

    if decrypted.len() < 16 {
        return Err(VersionError::Other("decrypted data too short".into()));
    }
    let decrypted_salt = &decrypted[..16];
    let kms_request_data = &decrypted[16..];

    let kms_request = KmsRequest::parse(kms_request_data)?;
    let response = server_logic(&kms_request, config);
    let response_bytes = response.marshal();

    let random_salt_bytes = random_salt();
    let hash_result = Sha256::digest(&random_salt_bytes);

    if is_v6 {
        build_v6_response(
            &response_bytes,
            salt,
            decrypted_salt,
            &random_salt_bytes,
            &hash_result,
            config,
            kms_request.request_time,
            version_minor,
            version_major,
        )
    } else {
        build_v5_response(
            &response_bytes,
            salt,
            decrypted_salt,
            &random_salt_bytes,
            &hash_result,
            version_minor,
            version_major,
        )
    }
}

#[allow(clippy::too_many_arguments)]
fn build_v5_response(
    response_bytes: &[u8],
    salt: &[u8],
    decrypted_salt: &[u8],
    random_salt_bytes: &[u8; 16],
    hash_result: &[u8],
    version_minor: u16,
    version_major: u16,
) -> Result<Vec<u8>, VersionError> {
    let rd_len = response_bytes.len() + 16 + 32;
    let mut buf = Vec::with_capacity(rd_len);
    buf.extend_from_slice(response_bytes);
    for i in 0..16 {
        buf.push(decrypted_salt[i] ^ salt[i] ^ random_salt_bytes[i]);
    }
    buf.extend_from_slice(hash_result);
    let padded = pkcs7_pad(&buf, 16);
    let encrypted = kms_encrypt_cbc(&padded, salt, false)?;
    Ok(build_v5_v6_response(version_minor, version_major, salt, &encrypted))
}

#[allow(clippy::too_many_arguments)]
fn build_v6_response(
    response_bytes: &[u8],
    salt: &[u8],
    decrypted_salt: &[u8],
    random_salt_bytes: &[u8; 16],
    hash_result: &[u8],
    config: &ServerConfig,
    request_time: u64,
    version_minor: u16,
    version_major: u16,
) -> Result<Vec<u8>, VersionError> {
    // messageBytes = response + randomStuff(16) + hash(32) + hwid + xorSalts(16)
    let mut message_bytes = Vec::with_capacity(response_bytes.len() + 16 + 32 + config.hwid.len() + 16 + 16);
    message_bytes.extend_from_slice(response_bytes);
    for i in 0..16 {
        message_bytes.push(salt[i] ^ decrypted_salt[i] ^ random_salt_bytes[i]);
    }
    message_bytes.extend_from_slice(hash_result);
    message_bytes.extend_from_slice(&config.hwid);
    for i in 0..16 {
        message_bytes.push(salt[i] ^ decrypted_salt[i]);
    }

    let salt_s = random_salt();
    let dsalt_s = kms_decrypt_cbc(&salt_s, &salt_s, true)?;

    let hmac_key = v6_mac_key(request_time);
    let mut xor_salts = [0u8; 16];
    for i in 0..16 {
        xor_salts[i] = salt_s[i] ^ dsalt_s[i];
    }
    let hmac_digest = v6_hmac_parts(&hmac_key, &[&xor_salts, &message_bytes]);
    message_bytes.extend_from_slice(&hmac_digest[16..]);

    let padded = pkcs7_pad(&message_bytes, 16);
    let encrypted = kms_encrypt_cbc(&padded, &salt_s, true)?;

    Ok(build_v5_v6_response(version_minor, version_major, &salt_s, &encrypted))
}

fn build_v5_v6_response(
    version_minor: u16,
    version_major: u16,
    iv: &[u8],
    encrypted: &[u8],
) -> Vec<u8> {
    let body_length = (2 + 2 + iv.len() + encrypted.len()) as u32;
    let padding = vec![0u8; get_padding(body_length as usize)];
    let total = 4 + 4 + 4 + 2 + 2 + iv.len() + encrypted.len() + padding.len();
    let mut resp = Vec::with_capacity(total);
    resp.extend_from_slice(&body_length.to_le_bytes());
    resp.extend_from_slice(&0x00000200u32.to_be_bytes());
    resp.extend_from_slice(&body_length.to_le_bytes());
    resp.extend_from_slice(&version_minor.to_le_bytes());
    resp.extend_from_slice(&version_major.to_le_bytes());
    resp.extend_from_slice(iv);
    resp.extend_from_slice(encrypted);
    resp.extend_from_slice(&padding);
    resp
}
