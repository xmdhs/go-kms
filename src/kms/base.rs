// KMS request/response wire format and server logic — mirrors reference/kms/base.go.

use std::sync::Mutex;

use super::utf16::encode_utf16le;
use super::uuid::KmsUuid;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KmsError {
    TooShort(&'static str, usize),
    EpidLengthMismatch,
}

impl std::fmt::Display for KmsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KmsError::TooShort(what, got) => write!(f, "{} too short: {}", what, got),
            KmsError::EpidLengthMismatch => write!(f, "KMS response EPID length mismatch"),
        }
    }
}
impl std::error::Error for KmsError {}

// ---------- KMSRequest ----------

pub const KMS_REQUEST_FIXED_SIZE: usize = 108;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KmsRequest {
    pub version_minor: u16,
    pub version_major: u16,
    pub is_client_vm: u32,
    pub license_status: u32,
    pub grace_time: u32,
    pub application_id: KmsUuid,
    pub sku_id: KmsUuid,
    pub kms_counted_id: KmsUuid,
    pub client_machine_id: KmsUuid,
    pub required_client_count: u32,
    pub request_time: u64,
    pub previous_client_machine_id: KmsUuid,
    pub machine_name_raw: Vec<u8>, // UTF-16LE padded blob
}

impl KmsRequest {
    pub fn parse(data: &[u8]) -> Result<Self, KmsError> {
        if data.len() < KMS_REQUEST_FIXED_SIZE {
            return Err(KmsError::TooShort("KMS request data", data.len()));
        }
        let mut off = 0usize;
        let version_minor = u16::from_le_bytes([data[off], data[off + 1]]);
        off += 2;
        let version_major = u16::from_le_bytes([data[off], data[off + 1]]);
        off += 2;
        let is_client_vm = read_u32_le(&data[off..]);
        off += 4;
        let license_status = read_u32_le(&data[off..]);
        off += 4;
        let grace_time = read_u32_le(&data[off..]);
        off += 4;
        let application_id = read_uuid(&data[off..]);
        off += 16;
        let sku_id = read_uuid(&data[off..]);
        off += 16;
        let kms_counted_id = read_uuid(&data[off..]);
        off += 16;
        let client_machine_id = read_uuid(&data[off..]);
        off += 16;
        let required_client_count = read_u32_le(&data[off..]);
        off += 4;
        let request_time = read_u64_le(&data[off..]);
        off += 8;
        let previous_client_machine_id = read_uuid(&data[off..]);
        off += 16;
        let machine_name_raw = if data.len() > off {
            data[off..].to_vec()
        } else {
            Vec::new()
        };

        Ok(Self {
            version_minor,
            version_major,
            is_client_vm,
            license_status,
            grace_time,
            application_id,
            sku_id,
            kms_counted_id,
            client_machine_id,
            required_client_count,
            request_time,
            previous_client_machine_id,
            machine_name_raw,
        })
    }

    pub fn marshal(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(KMS_REQUEST_FIXED_SIZE + self.machine_name_raw.len());
        out.extend_from_slice(&self.version_minor.to_le_bytes());
        out.extend_from_slice(&self.version_major.to_le_bytes());
        out.extend_from_slice(&self.is_client_vm.to_le_bytes());
        out.extend_from_slice(&self.license_status.to_le_bytes());
        out.extend_from_slice(&self.grace_time.to_le_bytes());
        out.extend_from_slice(self.application_id.as_bytes());
        out.extend_from_slice(self.sku_id.as_bytes());
        out.extend_from_slice(self.kms_counted_id.as_bytes());
        out.extend_from_slice(self.client_machine_id.as_bytes());
        out.extend_from_slice(&self.required_client_count.to_le_bytes());
        out.extend_from_slice(&self.request_time.to_le_bytes());
        out.extend_from_slice(self.previous_client_machine_id.as_bytes());
        out.extend_from_slice(&self.machine_name_raw);
        out
    }
}

// ---------- KMSResponse ----------

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KmsResponse {
    pub version_minor: u16,
    pub version_major: u16,
    pub epid_len: u32,
    pub kms_epid: Vec<u8>, // UTF-16LE bytes (without trailing 0x0000)
    pub client_machine_id: KmsUuid,
    pub response_time: u64,
    pub current_client_count: u32,
    pub vl_activation_interval: u32,
    pub vl_renewal_interval: u32,
}

impl KmsResponse {
    pub fn marshal(&self) -> Vec<u8> {
        let epid_len = (self.kms_epid.len() + 2) as u32; // +2 for null terminator
        let total = 44usize + epid_len as usize;
        let mut out = Vec::with_capacity(total);
        out.extend_from_slice(&self.version_minor.to_le_bytes());
        out.extend_from_slice(&self.version_major.to_le_bytes());
        out.extend_from_slice(&epid_len.to_le_bytes());
        out.extend_from_slice(&self.kms_epid);
        out.push(0);
        out.push(0);
        out.extend_from_slice(self.client_machine_id.as_bytes());
        out.extend_from_slice(&self.response_time.to_le_bytes());
        out.extend_from_slice(&self.current_client_count.to_le_bytes());
        out.extend_from_slice(&self.vl_activation_interval.to_le_bytes());
        out.extend_from_slice(&self.vl_renewal_interval.to_le_bytes());
        out
    }

    pub fn parse(data: &[u8]) -> Result<Self, KmsError> {
        if data.len() < 12 {
            return Err(KmsError::TooShort("KMS response data", data.len()));
        }
        let mut off = 0;
        let version_minor = u16::from_le_bytes([data[off], data[off + 1]]);
        off += 2;
        let version_major = u16::from_le_bytes([data[off], data[off + 1]]);
        off += 2;
        let epid_len = read_u32_le(&data[off..]);
        off += 4;
        let epid_end = off + epid_len as usize;
        if epid_end > data.len() {
            return Err(KmsError::EpidLengthMismatch);
        }
        let kms_epid = data[off..epid_end].to_vec();
        off = epid_end;
        const TAIL: usize = 16 + 8 + 4 + 4 + 4;
        if off + TAIL > data.len() {
            return Err(KmsError::TooShort("KMS response data for fixed fields", data.len()));
        }
        let client_machine_id = read_uuid(&data[off..]);
        off += 16;
        let response_time = read_u64_le(&data[off..]);
        off += 8;
        let current_client_count = read_u32_le(&data[off..]);
        off += 4;
        let vl_activation_interval = read_u32_le(&data[off..]);
        off += 4;
        let vl_renewal_interval = read_u32_le(&data[off..]);
        Ok(Self {
            version_minor,
            version_major,
            epid_len,
            kms_epid,
            client_machine_id,
            response_time,
            current_client_count,
            vl_activation_interval,
            vl_renewal_interval,
        })
    }
}

// ---------- GenericRequestHeader ----------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GenericRequestHeader {
    pub body_length1: u32,
    pub body_length2: u32,
    pub version_minor: u16,
    pub version_major: u16,
}

impl GenericRequestHeader {
    pub fn parse(data: &[u8]) -> Result<Self, KmsError> {
        if data.len() < 12 {
            return Err(KmsError::TooShort("generic request header", data.len()));
        }
        Ok(Self {
            body_length1: read_u32_le(&data[0..]),
            body_length2: read_u32_le(&data[4..]),
            version_minor: u16::from_le_bytes([data[8], data[9]]),
            version_major: u16::from_le_bytes([data[10], data[11]]),
        })
    }
}

// ---------- License states ----------

pub fn license_state_name(state: u32) -> &'static str {
    match state {
        0 => "Unlicensed",
        1 => "Activated",
        2 => "Grace Period",
        3 => "Out-of-Tolerance Grace Period",
        4 => "Non-Genuine Grace Period",
        5 => "Notifications Mode",
        6 => "Extended Grace Period",
        _ => "Unknown",
    }
}

// ---------- ServerConfig ----------

#[derive(Debug)]
pub struct ServerConfig {
    pub ip: String,
    pub port: u16,
    pub epid: String,
    pub lcid: i32,
    pub client_count: Option<u32>,
    pub activation: u32,
    pub renewal: u32,
    pub hwid: Vec<u8>,
    pub log_level: String,
    // cached UTF-16LE epid, materialized on first response.
    cached_epid: Mutex<Option<Vec<u8>>>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        let hwid = vec![0x36, 0x4F, 0x46, 0x3A, 0x88, 0x63, 0xD3, 0x5F];
        Self {
            ip: "0.0.0.0".into(),
            port: 1688,
            epid: String::new(),
            lcid: 1033,
            client_count: None,
            activation: 120,
            renewal: 10080,
            hwid,
            log_level: "DEBUG".into(),
            cached_epid: Mutex::new(None),
        }
    }
}

impl ServerConfig {
    /// Returns the UTF-16LE encoded ePID, generating one on first call if the user supplied none.
    /// Matches Go's epidOnce semantics.
    pub fn epid_bytes(&self) -> Vec<u8> {
        let mut guard = self.cached_epid.lock().unwrap();
        if let Some(b) = guard.as_ref() {
            return b.clone();
        }
        let bytes = if self.epid.is_empty() {
            encode_utf16le(&KmsUuid::random().to_string())
        } else {
            encode_utf16le(&self.epid)
        };
        *guard = Some(bytes.clone());
        bytes
    }

    /// Force-set the ePID bytes (test helper).
    pub fn set_epid_bytes(&self, bytes: Vec<u8>) {
        *self.cached_epid.lock().unwrap() = Some(bytes);
    }
}

// ---------- Server logic ----------

/// Computes the response data (without RPC framing or transport-layer crypto).
/// Mirrors Go's ServerLogic.
pub fn server_logic(req: &KmsRequest, config: &ServerConfig) -> KmsResponse {
    let min_clients = req.required_client_count;
    let required = min_clients.wrapping_mul(2);
    let current = match config.client_count {
        Some(cc) => {
            if cc > 0 && cc < min_clients {
                min_clients + 1
            } else if cc >= min_clients && cc < required {
                cc
            } else if cc >= required {
                required
            } else {
                0
            }
        }
        None => required,
    };

    KmsResponse {
        version_minor: req.version_minor,
        version_major: req.version_major,
        epid_len: 0, // computed in marshal
        kms_epid: config.epid_bytes(),
        client_machine_id: req.client_machine_id,
        response_time: req.request_time,
        current_client_count: current,
        vl_activation_interval: config.activation,
        vl_renewal_interval: config.renewal,
    }
}

// ---------- Padding helper ----------

pub fn get_padding(body_length: usize) -> usize {
    // Matches Go: 4 + (((^body) & 3) + 1) & 3
    // Using i32 to mirror Go's signed math, but body_length is always small.
    let not_body = !(body_length as u32);
    4 + (((not_body & 3) + 1) & 3) as usize
}

// ---------- Helpers ----------

pub(crate) fn read_u32_le(s: &[u8]) -> u32 {
    u32::from_le_bytes([s[0], s[1], s[2], s[3]])
}
pub(crate) fn read_u64_le(s: &[u8]) -> u64 {
    let mut a = [0u8; 8];
    a.copy_from_slice(&s[..8]);
    u64::from_le_bytes(a)
}
pub(crate) fn read_uuid(s: &[u8]) -> KmsUuid {
    let mut b = [0u8; 16];
    b.copy_from_slice(&s[..16]);
    KmsUuid(b)
}
