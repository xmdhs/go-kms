// Hardware-accelerated AES block primitives — mirrors the Go reference
// assembly (reference/crypto/aes_amd64.s and aes_arm64.s) using stable
// `core::arch` SIMD intrinsics. Round-key layout matches Go's
// `buildAsmRoundKeys` exactly: raw 16-byte chunks from `expand_key`, no
// column-major transpose. V6 patches and InvMixColumns are applied at
// key-build time so the runtime path is the same shape as Go's asm loops.
//
// Availability is detected at runtime via `is_x86_feature_detected!("aes")`
// on x86_64 and `is_aarch64_feature_detected!("aes")` on aarch64. On any
// other target `hw_aes_available()` returns false and the portable path
// remains in use.

use std::sync::OnceLock;

use super::aes::{apply_v6_round_patches, expand_key, mul_table, V4_KEY, V5_KEY, V6_KEY};

#[derive(Clone)]
pub struct HwRoundKeys {
    pub enc: Vec<[u8; 16]>,
    pub dec: Vec<[u8; 16]>,
}

fn inv_mix_columns_round_key(mut key: [u8; 16]) -> [u8; 16] {
    let m9 = mul_table(9);
    let m11 = mul_table(11);
    let m13 = mul_table(13);
    let m14 = mul_table(14);
    for col in 0..4 {
        let off = col * 4;
        let (a0, a1, a2, a3) = (key[off], key[off + 1], key[off + 2], key[off + 3]);
        key[off] = m14[a0 as usize] ^ m11[a1 as usize] ^ m13[a2 as usize] ^ m9[a3 as usize];
        key[off + 1] = m9[a0 as usize] ^ m14[a1 as usize] ^ m11[a2 as usize] ^ m13[a3 as usize];
        key[off + 2] = m13[a0 as usize] ^ m9[a1 as usize] ^ m14[a2 as usize] ^ m11[a3 as usize];
        key[off + 3] = m11[a0 as usize] ^ m13[a1 as usize] ^ m9[a2 as usize] ^ m14[a3 as usize];
    }
    key
}

fn build_hw_round_keys(expanded: &[u8], rounds: usize, patch_v6: bool) -> HwRoundKeys {
    let mut enc = vec![[0u8; 16]; rounds + 1];
    for i in 0..=rounds {
        enc[i].copy_from_slice(&expanded[i * 16..(i + 1) * 16]);
    }
    if patch_v6 {
        apply_v6_round_patches(&mut enc);
    }
    let mut dec = vec![[0u8; 16]; rounds + 1];
    dec[0] = enc[rounds];
    for i in 1..rounds {
        dec[i] = inv_mix_columns_round_key(enc[rounds - i]);
    }
    dec[rounds] = enc[0];
    HwRoundKeys { enc, dec }
}

pub fn v4_hw_keys() -> &'static HwRoundKeys {
    static C: OnceLock<HwRoundKeys> = OnceLock::new();
    C.get_or_init(|| build_hw_round_keys(&expand_key(&V4_KEY, 20, 192), 11, false))
}

pub fn v5_hw_keys() -> &'static HwRoundKeys {
    static C: OnceLock<HwRoundKeys> = OnceLock::new();
    C.get_or_init(|| build_hw_round_keys(&expand_key(&V5_KEY, 16, 176), 10, false))
}

pub fn v6_hw_keys() -> &'static HwRoundKeys {
    static C: OnceLock<HwRoundKeys> = OnceLock::new();
    C.get_or_init(|| build_hw_round_keys(&expand_key(&V6_KEY, 16, 176), 10, true))
}

// ---------- runtime feature detection ----------

#[cfg(target_arch = "x86_64")]
pub fn hw_aes_available() -> bool {
    static C: OnceLock<bool> = OnceLock::new();
    *C.get_or_init(|| std::is_x86_feature_detected!("aes"))
}

#[cfg(target_arch = "aarch64")]
pub fn hw_aes_available() -> bool {
    static C: OnceLock<bool> = OnceLock::new();
    *C.get_or_init(|| std::arch::is_aarch64_feature_detected!("aes"))
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
pub fn hw_aes_available() -> bool {
    false
}

// ---------- x86_64 AES-NI path ----------

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "aes")]
unsafe fn encrypt_block_x86(rounds: usize, keys: &[[u8; 16]], input: &[u8], out: &mut [u8]) {
    use core::arch::x86_64::*;
    let mut state = _mm_loadu_si128(input.as_ptr() as *const __m128i);
    state = _mm_xor_si128(state, _mm_loadu_si128(keys[0].as_ptr() as *const __m128i));
    for i in 1..rounds {
        state = _mm_aesenc_si128(state, _mm_loadu_si128(keys[i].as_ptr() as *const __m128i));
    }
    state = _mm_aesenclast_si128(state, _mm_loadu_si128(keys[rounds].as_ptr() as *const __m128i));
    _mm_storeu_si128(out.as_mut_ptr() as *mut __m128i, state);
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "aes")]
unsafe fn decrypt_block_x86(rounds: usize, keys: &[[u8; 16]], input: &[u8], out: &mut [u8]) {
    use core::arch::x86_64::*;
    let mut state = _mm_loadu_si128(input.as_ptr() as *const __m128i);
    state = _mm_xor_si128(state, _mm_loadu_si128(keys[0].as_ptr() as *const __m128i));
    for i in 1..rounds {
        state = _mm_aesdec_si128(state, _mm_loadu_si128(keys[i].as_ptr() as *const __m128i));
    }
    state = _mm_aesdeclast_si128(state, _mm_loadu_si128(keys[rounds].as_ptr() as *const __m128i));
    _mm_storeu_si128(out.as_mut_ptr() as *mut __m128i, state);
}

// ---------- aarch64 ARMv8 AES path ----------

#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "aes")]
unsafe fn encrypt_block_arm(rounds: usize, keys: &[[u8; 16]], input: &[u8], out: &mut [u8]) {
    use core::arch::aarch64::*;
    let mut state = vld1q_u8(input.as_ptr());
    for i in 0..rounds - 1 {
        let rk = vld1q_u8(keys[i].as_ptr());
        state = vaesmcq_u8(vaeseq_u8(state, rk));
    }
    let rk = vld1q_u8(keys[rounds - 1].as_ptr());
    state = vaeseq_u8(state, rk);
    let rk = vld1q_u8(keys[rounds].as_ptr());
    state = veorq_u8(state, rk);
    vst1q_u8(out.as_mut_ptr(), state);
}

#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "aes")]
unsafe fn decrypt_block_arm(rounds: usize, keys: &[[u8; 16]], input: &[u8], out: &mut [u8]) {
    use core::arch::aarch64::*;
    let mut state = vld1q_u8(input.as_ptr());
    for i in 0..rounds - 1 {
        let rk = vld1q_u8(keys[i].as_ptr());
        state = vaesimcq_u8(vaesdq_u8(state, rk));
    }
    let rk = vld1q_u8(keys[rounds - 1].as_ptr());
    state = vaesdq_u8(state, rk);
    let rk = vld1q_u8(keys[rounds].as_ptr());
    state = veorq_u8(state, rk);
    vst1q_u8(out.as_mut_ptr(), state);
}

// ---------- dispatcher (callers must gate on `hw_aes_available()`) ----------

#[inline]
pub fn aes_encrypt_block_hw(rounds: usize, keys: &[[u8; 16]], input: &[u8], out: &mut [u8]) {
    debug_assert!(input.len() >= 16 && out.len() >= 16);
    debug_assert!(keys.len() > rounds);
    #[cfg(target_arch = "x86_64")]
    unsafe {
        encrypt_block_x86(rounds, keys, input, out);
    }
    #[cfg(target_arch = "aarch64")]
    unsafe {
        encrypt_block_arm(rounds, keys, input, out);
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        let _ = (rounds, keys, input, out);
        unreachable!("aes_encrypt_block_hw called without a hardware AES backend");
    }
}

#[inline]
pub fn aes_decrypt_block_hw(rounds: usize, keys: &[[u8; 16]], input: &[u8], out: &mut [u8]) {
    debug_assert!(input.len() >= 16 && out.len() >= 16);
    debug_assert!(keys.len() > rounds);
    #[cfg(target_arch = "x86_64")]
    unsafe {
        decrypt_block_x86(rounds, keys, input, out);
    }
    #[cfg(target_arch = "aarch64")]
    unsafe {
        decrypt_block_arm(rounds, keys, input, out);
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        let _ = (rounds, keys, input, out);
        unreachable!("aes_decrypt_block_hw called without a hardware AES backend");
    }
}
