// V4 hash — custom AES-CMAC-like construction using the V4 (160-bit) block cipher.

use super::kms_aes::aes_encrypt_block_v4;

pub fn v4_hash(message: &[u8]) -> [u8; 16] {
    let message_size = message.len();
    let mut hash_buffer = [0u8; 16];
    let mut encrypted = [0u8; 16];

    let j = message_size >> 4; // number of full 16-byte blocks
    let k = message_size & 0xf; // remaining bytes

    for i in 0..j {
        let base = i * 16;
        for b in 0..16 {
            hash_buffer[b] ^= message[base + b];
        }
        aes_encrypt_block_v4(&hash_buffer, &mut encrypted);
        hash_buffer = encrypted;
    }

    let mut last_block = [0u8; 16];
    for i in 0..k {
        last_block[i] = message[j * 16 + i];
    }
    last_block[k] = 0x80;

    for b in 0..16 {
        hash_buffer[b] ^= last_block[b];
    }
    aes_encrypt_block_v4(&hash_buffer, &mut encrypted);
    encrypted
}
