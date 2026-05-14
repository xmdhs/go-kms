// Unit tests for the kms module — UUID, filetime, UTF-16, KmsRequest/Response.

use kms_rs::kms::base::{
    get_padding, server_logic, KmsRequest, KmsResponse, ServerConfig,
};
use kms_rs::kms::filetime::{filetime_to_unix, unix_to_filetime, EPOCH_AS_FILETIME};
use kms_rs::kms::utf16::{decode_utf16le, encode_utf16le};
use kms_rs::kms::uuid::{must_uuid, KmsUuid};

#[test]
fn uuid_string_round_trip() {
    let s = "01234567-89ab-cdef-0123-456789abcdef";
    let u = must_uuid(s);
    assert_eq!(u.to_string(), s);
}

#[test]
fn uuid_parse_accepts_32_and_36_chars() {
    let a = must_uuid("01234567-89ab-cdef-0123-456789abcdef");
    let b = must_uuid("0123456789abcdef0123456789abcdef");
    // The 32-char form has no LE swap of the first three groups during parse,
    // so it represents a different on-wire value. Verify both are non-zero.
    assert_ne!(a.as_bytes(), &[0u8; 16]);
    assert_ne!(b.as_bytes(), &[0u8; 16]);
}

#[test]
fn uuid_bytes_le_format() {
    // 01234567-89ab-cdef-... -> bytes_le first 4 = 67 45 23 01.
    let u = must_uuid("01234567-89ab-cdef-0123-456789abcdef");
    let b = u.as_bytes();
    assert_eq!(b[0], 0x67);
    assert_eq!(b[1], 0x45);
    assert_eq!(b[2], 0x23);
    assert_eq!(b[3], 0x01);
    assert_eq!(b[4], 0xab);
    assert_eq!(b[5], 0x89);
    assert_eq!(b[6], 0xef);
    assert_eq!(b[7], 0xcd);
    assert_eq!(b[8], 0x01);
    assert_eq!(b[15], 0xef);
}

#[test]
fn utf16le_roundtrip() {
    let s = "Windows8.1";
    let enc = encode_utf16le(s);
    let decoded = decode_utf16le(&enc);
    assert_eq!(decoded, s);
}

#[test]
fn utf16le_strips_trailing_nulls() {
    let mut enc = encode_utf16le("ABC");
    enc.push(0);
    enc.push(0);
    enc.push(0);
    enc.push(0);
    assert_eq!(decode_utf16le(&enc), "ABC");
}

#[test]
fn filetime_round_trip() {
    for ft in [EPOCH_AS_FILETIME, EPOCH_AS_FILETIME + 10_000_000, 132580512000000000i64] {
        let (secs, nanos) = filetime_to_unix(ft);
        let back = unix_to_filetime(secs, nanos);
        assert_eq!(back, ft);
    }
}

#[test]
fn padding_formula_matches_go() {
    // Go: GetPadding(body_length) = 4 + (((^body) & 3) + 1) & 3
    // Always pads to a multiple of 4, with at least 4 bytes of padding.
    assert_eq!(get_padding(0), 4);
    assert_eq!(get_padding(1), 7);
    assert_eq!(get_padding(2), 6);
    assert_eq!(get_padding(3), 5);
    assert_eq!(get_padding(4), 4);
    assert_eq!(get_padding(5), 7);
}

#[test]
fn kms_request_marshal_parse_round_trip() {
    let req = KmsRequest {
        version_minor: 0,
        version_major: 6,
        is_client_vm: 1,
        license_status: 2,
        grace_time: 43200 * 2,
        application_id: must_uuid("55c92734-d682-4d71-983e-d6ec3f16059f"),
        sku_id: must_uuid("81671aaf-79d1-4eb1-b004-8cbbe173afea"),
        kms_counted_id: must_uuid("cb8fc780-2c05-495a-9710-85afffc904d7"),
        client_machine_id: must_uuid("01234567-89ab-cdef-0123-456789abcdef"),
        required_client_count: 25,
        request_time: 132580512000000000,
        previous_client_machine_id: KmsUuid::default(),
        machine_name_raw: vec![0u8; 128],
    };
    let wire = req.marshal();
    let parsed = KmsRequest::parse(&wire).unwrap();
    assert_eq!(parsed, req);
}

#[test]
fn server_logic_uses_required_clients() {
    let mut cfg = ServerConfig::default();
    cfg.epid = "fixed-epid".into();
    let req = KmsRequest {
        required_client_count: 25,
        ..Default::default()
    };
    let resp = server_logic(&req, &cfg);
    assert_eq!(resp.current_client_count, 50);
    assert_eq!(resp.vl_activation_interval, 120);
    assert_eq!(resp.vl_renewal_interval, 10080);
}

#[test]
fn kms_response_marshal_includes_null_terminator() {
    let resp = KmsResponse {
        version_minor: 0,
        version_major: 6,
        epid_len: 0, // computed inside marshal
        kms_epid: encode_utf16le("X"),
        client_machine_id: KmsUuid::default(),
        response_time: 0,
        current_client_count: 0,
        vl_activation_interval: 0,
        vl_renewal_interval: 0,
    };
    let wire = resp.marshal();
    let parsed = KmsResponse::parse(&wire).unwrap();
    // kms_epid had 2 bytes (1 utf16 code unit), epid_len is len+2 = 4.
    assert_eq!(parsed.epid_len, 4);
}
