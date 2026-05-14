// Unit tests for the crypto module — mirrors reference/crypto/aes_test.go.

use kms_rs::crypto::kms_aes::{
    kms_decrypt_cbc, kms_encrypt_cbc, pkcs7_pad, pkcs7_unpad, CryptoError,
};
use kms_rs::crypto::v4_hash::v4_hash;
use kms_rs::crypto::v6_mac::{v6_hmac, v6_mac_key};

fn hex_encode(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for &x in b {
        s.push_str(&format!("{:02x}", x));
    }
    s
}

#[test]
fn pkcs7_pad_empty_yields_full_block() {
    let got = pkcs7_pad(&[], 16);
    assert_eq!(got.len(), 16);
    assert!(got.iter().all(|&b| b == 16));
}

#[test]
fn pkcs7_pad_not_aligned() {
    let got = pkcs7_pad(b"abc", 16);
    assert_eq!(got.len(), 16);
    assert!(got[3..].iter().all(|&b| b == 13));
}

#[test]
fn pkcs7_pad_aligned_adds_full_block() {
    let got = pkcs7_pad(&[0x11; 16], 16);
    assert_eq!(got.len(), 32);
    assert!(got[16..].iter().all(|&b| b == 16));
}

#[test]
fn pkcs7_unpad_roundtrip() {
    let padded = pkcs7_pad(b"kms-test", 16);
    let unpadded = pkcs7_unpad(&padded).unwrap();
    assert_eq!(unpadded, b"kms-test");
}

#[test]
fn pkcs7_unpad_rejects_invalid() {
    assert!(matches!(pkcs7_unpad(&[]), Err(CryptoError::Empty)));
    assert!(matches!(pkcs7_unpad(&[1, 2, 3]), Err(CryptoError::NotBlockAligned(_))));
    let mut bad = vec![0x41; 16];
    bad[15] = 0x00;
    assert!(matches!(pkcs7_unpad(&bad), Err(CryptoError::InvalidPaddingValue(0))));
    let mut bad = vec![0x41; 16];
    bad[15] = 0x11; // padding > 16
    assert!(matches!(pkcs7_unpad(&bad), Err(CryptoError::InvalidPaddingValue(_))));
    let mut bad = vec![0x41; 16];
    bad[14] = 0x02;
    bad[15] = 0x03;
    assert!(matches!(pkcs7_unpad(&bad), Err(CryptoError::InvalidPaddingByte(_))));
}

#[test]
fn kms_cbc_round_trip_all_versions_and_lengths() {
    let iv: [u8; 16] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
        0x0F,
    ];
    for &v6 in &[false, true] {
        for &n in &[0usize, 1, 15, 16, 17, 31, 32, 63] {
            let plain: Vec<u8> = std::iter::repeat((n + 1) as u8).take(n).collect();
            let padded = pkcs7_pad(&plain, 16);
            let cipher = kms_encrypt_cbc(&padded, &iv, v6).unwrap();
            let decrypted = kms_decrypt_cbc(&cipher, &iv, v6).unwrap();
            let unpadded = pkcs7_unpad(&decrypted).unwrap();
            assert_eq!(unpadded, plain, "v6={} n={}", v6, n);
        }
    }
}

#[test]
fn stable_vectors_match_baseline() {
    let iv: [u8; 16] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
        0x0F,
    ];
    let plain = pkcs7_pad(b"baseline-vector-data", 16);
    let v5c = kms_encrypt_cbc(&plain, &iv, false).unwrap();
    let v6c = kms_encrypt_cbc(&plain, &iv, true).unwrap();
    assert_eq!(
        hex_encode(&v5c),
        "3de528e57853c743ede9ffbb4177d273792e4ec579be591cc4cdc8e1f970df76"
    );
    assert_eq!(
        hex_encode(&v6c),
        "72e5d15d6c3ec1cf9f3b035cef80c853eea1766833d799e008648877675ca750"
    );

    let h = v4_hash(b"baseline-v4-hash-input");
    assert_eq!(hex_encode(&h), "7f2db248dc798b8bc805f6e330a9b06b");

    let k = v6_mac_key(13322345678901234567);
    assert_eq!(hex_encode(&k), "8012fac9c77fb0f401b438c8b96f4e1d");

    let m = v6_hmac(&k, b"baseline-v6-hmac-input");
    assert_eq!(
        hex_encode(&m),
        "27214d078c7f492a71a86a75ccc0f83a31fcf1f29529689c5a4add1ddd17a148"
    );
}

#[test]
fn v4_hash_deterministic() {
    let h1 = v4_hash(b"fixed-v4-hash-input");
    let h2 = v4_hash(b"fixed-v4-hash-input");
    assert_eq!(h1, h2);
}
