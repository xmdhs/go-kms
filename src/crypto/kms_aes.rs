// KMS-specific block ciphers (V4 / V5 / V6) plus CBC and PKCS7 helpers.
// Output bytes match the Go fallback (portable) path exactly.

use std::sync::OnceLock;

use super::aes::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CryptoError {
    Empty,
    NotBlockAligned(usize),
    InvalidPaddingValue(u8),
    InvalidPaddingByte(usize),
    PlaintextNotBlockAligned,
    CiphertextNotBlockAligned,
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CryptoError::Empty => write!(f, "empty data"),
            CryptoError::NotBlockAligned(n) => {
                write!(f, "data length {} is not a multiple of 16", n)
            }
            CryptoError::InvalidPaddingValue(v) => write!(f, "invalid PKCS7 padding: {}", v),
            CryptoError::InvalidPaddingByte(i) => {
                write!(f, "invalid PKCS7 padding byte at position {}", i)
            }
            CryptoError::PlaintextNotBlockAligned => {
                write!(f, "plaintext is not a multiple of block size")
            }
            CryptoError::CiphertextNotBlockAligned => {
                write!(f, "ciphertext is not a multiple of block size")
            }
        }
    }
}

impl std::error::Error for CryptoError {}

// ---------- PKCS7 ----------

pub fn pkcs7_pad(data: &[u8], block_size: usize) -> Vec<u8> {
    let padding = block_size - data.len() % block_size;
    let mut out = Vec::with_capacity(data.len() + padding);
    out.extend_from_slice(data);
    out.resize(data.len() + padding, padding as u8);
    out
}

pub fn pkcs7_unpad(data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if data.is_empty() {
        return Err(CryptoError::Empty);
    }
    if data.len() % 16 != 0 {
        return Err(CryptoError::NotBlockAligned(data.len()));
    }
    let padding = data[data.len() - 1];
    if padding == 0 || padding > 16 {
        return Err(CryptoError::InvalidPaddingValue(padding));
    }
    let p = padding as usize;
    for i in (data.len() - p)..data.len() {
        if data[i] != padding {
            return Err(CryptoError::InvalidPaddingByte(i));
        }
    }
    Ok(data[..data.len() - p].to_vec())
}

// ---------- round-key caches ----------

fn v5_round_keys() -> &'static Vec<[u8; 16]> {
    static C: OnceLock<Vec<[u8; 16]>> = OnceLock::new();
    C.get_or_init(|| build_round_keys(&expand_key(&V5_KEY, 16, 176), 10))
}

fn v6_round_keys() -> &'static Vec<[u8; 16]> {
    static C: OnceLock<Vec<[u8; 16]>> = OnceLock::new();
    C.get_or_init(|| {
        let mut rk = build_round_keys(&expand_key(&V6_KEY, 16, 176), 10);
        apply_v6_round_patches(&mut rk);
        rk
    })
}

fn v4_round_keys() -> &'static Vec<[u8; 16]> {
    static C: OnceLock<Vec<[u8; 16]>> = OnceLock::new();
    C.get_or_init(|| build_round_keys(&expand_key(&V4_KEY, 20, 192), 11))
}

// ---------- Block encrypt/decrypt (V4 = 11 rounds, V5/V6 = 10 rounds) ----------

fn encrypt_block_generic(round_keys: &[[u8; 16]], rounds: usize, input: &[u8], out: &mut [u8]) {
    let mut state = state_from_input(input);
    add_round_key(&mut state, &round_keys[0]);
    for i in 1..rounds {
        sub_bytes(&mut state, false);
        shift_rows(&mut state, false);
        mix_columns(&mut state, false);
        add_round_key(&mut state, &round_keys[i]);
    }
    sub_bytes(&mut state, false);
    shift_rows(&mut state, false);
    add_round_key(&mut state, &round_keys[rounds]);
    state_to_output(&state, out);
}

fn decrypt_block_generic(round_keys: &[[u8; 16]], rounds: usize, input: &[u8], out: &mut [u8]) {
    let mut state = state_from_input(input);
    add_round_key(&mut state, &round_keys[rounds]);
    for i in (1..rounds).rev() {
        shift_rows(&mut state, true);
        sub_bytes(&mut state, true);
        add_round_key(&mut state, &round_keys[i]);
        mix_columns(&mut state, true);
    }
    shift_rows(&mut state, true);
    sub_bytes(&mut state, true);
    add_round_key(&mut state, &round_keys[0]);
    state_to_output(&state, out);
}

pub fn aes_encrypt_block_v4(input: &[u8], out: &mut [u8]) {
    encrypt_block_generic(v4_round_keys(), 11, input, out);
}
pub fn aes_decrypt_block_v4(input: &[u8], out: &mut [u8]) {
    decrypt_block_generic(v4_round_keys(), 11, input, out);
}
pub fn aes_encrypt_block_v5(input: &[u8], out: &mut [u8]) {
    encrypt_block_generic(v5_round_keys(), 10, input, out);
}
pub fn aes_decrypt_block_v5(input: &[u8], out: &mut [u8]) {
    decrypt_block_generic(v5_round_keys(), 10, input, out);
}
pub fn aes_encrypt_block_v6(input: &[u8], out: &mut [u8]) {
    encrypt_block_generic(v6_round_keys(), 10, input, out);
}
pub fn aes_decrypt_block_v6(input: &[u8], out: &mut [u8]) {
    decrypt_block_generic(v6_round_keys(), 10, input, out);
}

// ---------- AES-CBC (KMS V5 or V6) ----------

pub fn kms_encrypt_cbc(data: &[u8], iv: &[u8], v6: bool) -> Result<Vec<u8>, CryptoError> {
    if data.len() % 16 != 0 {
        return Err(CryptoError::PlaintextNotBlockAligned);
    }
    let mut out = vec![0u8; data.len()];
    let mut prev = [0u8; 16];
    prev.copy_from_slice(&iv[..16]);
    let mut block = [0u8; 16];
    let mut encrypted = [0u8; 16];

    let enc_fn: fn(&[u8], &mut [u8]) = if v6 {
        aes_encrypt_block_v6
    } else {
        aes_encrypt_block_v5
    };

    let mut i = 0;
    while i < data.len() {
        for j in 0..16 {
            block[j] = data[i + j] ^ prev[j];
        }
        enc_fn(&block, &mut encrypted);
        out[i..i + 16].copy_from_slice(&encrypted);
        prev.copy_from_slice(&encrypted);
        i += 16;
    }
    Ok(out)
}

pub fn kms_decrypt_cbc(data: &[u8], iv: &[u8], v6: bool) -> Result<Vec<u8>, CryptoError> {
    if data.len() % 16 != 0 {
        return Err(CryptoError::CiphertextNotBlockAligned);
    }
    let mut out = vec![0u8; data.len()];
    let mut prev = [0u8; 16];
    prev.copy_from_slice(&iv[..16]);
    let mut decrypted = [0u8; 16];

    let dec_fn: fn(&[u8], &mut [u8]) = if v6 {
        aes_decrypt_block_v6
    } else {
        aes_decrypt_block_v5
    };

    let mut i = 0;
    while i < data.len() {
        dec_fn(&data[i..i + 16], &mut decrypted);
        for j in 0..16 {
            out[i + j] = decrypted[j] ^ prev[j];
        }
        prev.copy_from_slice(&data[i..i + 16]);
        i += 16;
    }
    Ok(out)
}

// ---------- Random salt ----------

pub fn random_salt() -> [u8; 16] {
    use rand::RngCore;
    let mut s = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut s);
    s
}
