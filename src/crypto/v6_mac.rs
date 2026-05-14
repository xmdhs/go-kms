// V6 HMAC and MAC key derivation.

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

const C1: u64 = 0x00000022816889BD;
const C2: u64 = 0x000000208CBAB5ED;
const C3: u64 = 0x3156CD5AC628477A;

/// Derive a 16-byte HMAC key from the request timestamp, matching Go's V6MACKey.
pub fn v6_mac_key(request_time: u64) -> [u8; 16] {
    // In Go: i1 = requestTime / c1 (unsigned u64 div, deterministic)
    //       i2 = i1 * c2 (wrapping)
    //       seed = i2 + c3 (wrapping)
    //       sha256(little-endian seed bytes), take digest[16..32]
    let i1 = request_time.wrapping_div(C1);
    let i2 = i1.wrapping_mul(C2);
    let seed = i2.wrapping_add(C3);

    let buf = seed.to_le_bytes();
    let digest = Sha256::digest(&buf);
    let mut key = [0u8; 16];
    key.copy_from_slice(&digest[16..32]);
    key
}

/// Compute HMAC-SHA256 over a single message (matches Go V6HMAC).
pub fn v6_hmac(mac_key: &[u8], data: &[u8]) -> [u8; 32] {
    v6_hmac_parts(mac_key, &[data])
}

/// Compute HMAC-SHA256 over a sequence of parts (matches Go V6HMACParts).
pub fn v6_hmac_parts(mac_key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(mac_key).expect("HMAC accepts any key length");
    for part in parts {
        mac.update(part);
    }
    let bytes = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    out
}
