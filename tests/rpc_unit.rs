// Unit tests for the rpc module — Bind/Request/Response byte-level layout.

use kms_rs::rpc::{
    build_bind_ack_response, build_bind_request, build_msrpc_response, build_rpc_request, pdu_data,
    MsRpcHeader, MsRpcRequestHeader, CTX_ITEM_SIZE, FLAG_CONC_MPX, FLAG_FIRST_FRAG, FLAG_LAST_FRAG,
    MSRPC_HEADER_SIZE, MSRPC_REQUEST_HEADER_SIZE, PACKET_TYPE_BIND, PACKET_TYPE_BIND_ACK,
    PACKET_TYPE_REQUEST, PACKET_TYPE_RESPONSE,
};

#[test]
fn bind_request_layout() {
    let b = build_bind_request(1);
    // 16-byte header + 12 + 2*44 = 100 body = 116 total.
    assert_eq!(b.len(), 116);
    let header = MsRpcHeader::parse(&b).unwrap();
    assert_eq!(header.ver_major, 5);
    assert_eq!(header.ver_minor, 0);
    assert_eq!(header.typ, PACKET_TYPE_BIND);
    assert_eq!(header.flags, FLAG_FIRST_FRAG | FLAG_LAST_FRAG | FLAG_CONC_MPX);
    assert_eq!(header.frag_len, 116);
    assert_eq!(header.call_id, 1);
}

#[test]
fn bind_ack_for_known_request() {
    let req = build_bind_request(1);
    let ack = build_bind_ack_response(&req, 1688, 1).unwrap();
    let h = MsRpcHeader::parse(&ack).unwrap();
    assert_eq!(h.typ, PACKET_TYPE_BIND_ACK);
    assert_eq!(h.frag_len as usize, ack.len());
    assert_eq!(h.call_id, 1);
}

#[test]
fn rpc_request_wraps_kms_data() {
    let data = vec![0xAA; 100];
    let pkt = build_rpc_request(&data, 2);
    let h = MsRpcRequestHeader::parse(&pkt).unwrap();
    assert_eq!(h.header.typ, PACKET_TYPE_REQUEST);
    assert_eq!(h.alloc_hint, 100);
    assert_eq!(h.ctx_id, 0);
    assert_eq!(h.op_num, 0);
    assert_eq!(pkt.len(), MSRPC_REQUEST_HEADER_SIZE + 100);
    let pdu = h.pdu_data(&pkt).unwrap();
    assert_eq!(pdu.len(), 100);
    assert!(pdu.iter().all(|&b| b == 0xAA));
}

#[test]
fn msrpc_response_inherits_call_id() {
    let req = build_rpc_request(&[1u8; 50], 0xDEAD_BEEF);
    let h = MsRpcRequestHeader::parse(&req).unwrap();
    let pdu = vec![0xCC; 30];
    let resp = build_msrpc_response(&h, &pdu);
    let rh = MsRpcHeader::parse(&resp).unwrap();
    assert_eq!(rh.typ, PACKET_TYPE_RESPONSE);
    assert_eq!(rh.call_id, 0xDEAD_BEEF);
    assert_eq!(rh.frag_len as usize, resp.len());
}

#[test]
fn pdu_data_returns_payload() {
    let req = build_rpc_request(&[7u8; 16], 1);
    let pdu = pdu_data(&req).unwrap();
    // PDU starts at offset 16 (header) — RPC request header lives at 16..24.
    assert_eq!(pdu.len(), req.len() - MSRPC_HEADER_SIZE);
}

#[test]
fn constants_match_sizes() {
    assert_eq!(CTX_ITEM_SIZE, 44);
    assert_eq!(MSRPC_HEADER_SIZE, 16);
    assert_eq!(MSRPC_REQUEST_HEADER_SIZE, 24);
}
