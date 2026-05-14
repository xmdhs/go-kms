// MS-RPC packet handling — mirrors reference/rpc/rpc.go byte for byte.

use tokio::io::{AsyncRead, AsyncReadExt};

// ---------- Packet type constants ----------

pub const PACKET_TYPE_REQUEST: u8 = 0x00;
pub const PACKET_TYPE_PING: u8 = 0x01;
pub const PACKET_TYPE_RESPONSE: u8 = 0x02;
pub const PACKET_TYPE_FAULT: u8 = 0x03;
pub const PACKET_TYPE_WORKING: u8 = 0x04;
pub const PACKET_TYPE_NO_CALL: u8 = 0x05;
pub const PACKET_TYPE_REJECT: u8 = 0x06;
pub const PACKET_TYPE_ACK: u8 = 0x07;
pub const PACKET_TYPE_CL_CANCEL: u8 = 0x08;
pub const PACKET_TYPE_FACK: u8 = 0x09;
pub const PACKET_TYPE_CANCEL_ACK: u8 = 0x0A;
pub const PACKET_TYPE_BIND: u8 = 0x0B;
pub const PACKET_TYPE_BIND_ACK: u8 = 0x0C;
pub const PACKET_TYPE_BIND_NAK: u8 = 0x0D;
pub const PACKET_TYPE_ALTER_CONTEXT: u8 = 0x0E;
pub const PACKET_TYPE_ALTER_CONTEXT_R: u8 = 0x0F;
pub const PACKET_TYPE_AUTH3: u8 = 0x10;
pub const PACKET_TYPE_SHUTDOWN: u8 = 0x11;
pub const PACKET_TYPE_CO_CANCEL: u8 = 0x12;
pub const PACKET_TYPE_ORPHANED: u8 = 0x13;

// ---------- Packet flag constants ----------

pub const FLAG_FIRST_FRAG: u8 = 0x01;
pub const FLAG_LAST_FRAG: u8 = 0x02;
pub const FLAG_SUPPORT_SIGN: u8 = 0x04;
pub const FLAG_PEND_CANCEL: u8 = 0x04;
pub const FLAG_RESERVED: u8 = 0x08;
pub const FLAG_CONC_MPX: u8 = 0x10;
pub const FLAG_DID_NOT_EXEC: u8 = 0x20;
pub const FLAG_MAYBE: u8 = 0x40;
pub const FLAG_OBJECT_UUID: u8 = 0x80;

pub const CONT_RESULT_ACCEPT: u16 = 0;
pub const CONT_RESULT_USER_REJECT: u16 = 1;
pub const CONT_RESULT_PROV_REJECT: u16 = 2;

pub const MSRPC_HEADER_SIZE: usize = 16;
pub const MSRPC_REQUEST_HEADER_SIZE: usize = 24;
pub const MSRPC_RESP_HEADER_SIZE: usize = 24;
pub const CTX_ITEM_SIZE: usize = 44;
pub const CTX_ITEM_RESULT_SIZE: usize = 24;

// ---------- Well-known UUIDs ----------

pub const UUID_NDR32: [u8; 16] = [
    0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11, 0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60,
];
pub const UUID_NDR64: [u8; 16] = [
    0x33, 0x05, 0x71, 0x71, 0xba, 0xbe, 0x37, 0x49, 0x83, 0x19, 0xb5, 0xdb, 0xef, 0x9c, 0xcc, 0x36,
];
pub const UUID_TIME: [u8; 16] = [
    0x2c, 0x1c, 0xb7, 0x6c, 0x12, 0x98, 0x40, 0x45, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];
pub const UUID_EMPTY: [u8; 16] = [0; 16];

pub const KMS_INTERFACE_UUID: [u8; 16] = [
    0x75, 0x21, 0xc8, 0x51, 0x4e, 0x84, 0x50, 0x47, 0xb0, 0xd8, 0xec, 0x25, 0x55, 0x55, 0xbc, 0x06,
];

// ---------- Errors ----------

#[derive(Debug)]
pub enum RpcError {
    TooShort(String),
    Io(std::io::Error),
}
impl std::fmt::Display for RpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RpcError::TooShort(s) => f.write_str(s),
            RpcError::Io(e) => write!(f, "{}", e),
        }
    }
}
impl std::error::Error for RpcError {}
impl From<std::io::Error> for RpcError {
    fn from(e: std::io::Error) -> Self {
        RpcError::Io(e)
    }
}

// ---------- MSRPCHeader ----------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MsRpcHeader {
    pub ver_major: u8,
    pub ver_minor: u8,
    pub typ: u8,
    pub flags: u8,
    pub representation: u32,
    pub frag_len: u16,
    pub auth_len: u16,
    pub call_id: u32,
}

impl MsRpcHeader {
    pub fn parse(data: &[u8]) -> Result<Self, RpcError> {
        if data.len() < MSRPC_HEADER_SIZE {
            return Err(RpcError::TooShort(format!(
                "data too short for RPC header: {}",
                data.len()
            )));
        }
        Ok(Self {
            ver_major: data[0],
            ver_minor: data[1],
            typ: data[2],
            flags: data[3],
            representation: u32::from_le_bytes([data[4], data[5], data[6], data[7]]),
            frag_len: u16::from_le_bytes([data[8], data[9]]),
            auth_len: u16::from_le_bytes([data[10], data[11]]),
            call_id: u32::from_le_bytes([data[12], data[13], data[14], data[15]]),
        })
    }

    pub fn marshal(&self) -> [u8; MSRPC_HEADER_SIZE] {
        let mut out = [0u8; MSRPC_HEADER_SIZE];
        out[0] = self.ver_major;
        out[1] = self.ver_minor;
        out[2] = self.typ;
        out[3] = self.flags;
        out[4..8].copy_from_slice(&self.representation.to_le_bytes());
        out[8..10].copy_from_slice(&self.frag_len.to_le_bytes());
        out[10..12].copy_from_slice(&self.auth_len.to_le_bytes());
        out[12..16].copy_from_slice(&self.call_id.to_le_bytes());
        out
    }
}

pub fn pdu_data(data: &[u8]) -> Option<&[u8]> {
    if data.len() <= MSRPC_HEADER_SIZE {
        return None;
    }
    let header = MsRpcHeader::parse(data).ok()?;
    let mut end = header.frag_len as usize - header.auth_len as usize;
    if header.auth_len > 0 {
        end = end.saturating_sub(8);
    }
    if end > data.len() {
        end = data.len();
    }
    if end <= MSRPC_HEADER_SIZE {
        return None;
    }
    Some(&data[MSRPC_HEADER_SIZE..end])
}

// ---------- MSRPCRequestHeader ----------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MsRpcRequestHeader {
    pub header: MsRpcHeader,
    pub alloc_hint: u32,
    pub ctx_id: u16,
    pub op_num: u16,
}

impl MsRpcRequestHeader {
    pub fn parse(data: &[u8]) -> Result<Self, RpcError> {
        if data.len() < MSRPC_REQUEST_HEADER_SIZE {
            return Err(RpcError::TooShort(format!(
                "data too short for RPC request header: {}",
                data.len()
            )));
        }
        let header = MsRpcHeader::parse(data)?;
        Ok(Self {
            header,
            alloc_hint: u32::from_le_bytes([data[16], data[17], data[18], data[19]]),
            ctx_id: u16::from_le_bytes([data[20], data[21]]),
            op_num: u16::from_le_bytes([data[22], data[23]]),
        })
    }

    pub fn pdu_data<'a>(&self, full_packet: &'a [u8]) -> Option<&'a [u8]> {
        if full_packet.len() <= MSRPC_REQUEST_HEADER_SIZE {
            return None;
        }
        let mut offset = MSRPC_REQUEST_HEADER_SIZE;
        if self.header.flags & FLAG_OBJECT_UUID > 0 {
            offset += 16;
        }
        let mut end = self.header.frag_len as usize - self.header.auth_len as usize;
        if self.header.auth_len > 0 {
            end = end.saturating_sub(8);
        }
        if end > full_packet.len() {
            end = full_packet.len();
        }
        if offset >= end {
            return None;
        }
        Some(&full_packet[offset..end])
    }
}

// ---------- MSRPCRespHeader (build only) ----------

pub fn build_msrpc_response(req_header: &MsRpcRequestHeader, pdu_data: &[u8]) -> Vec<u8> {
    let frag_len = (MSRPC_RESP_HEADER_SIZE + pdu_data.len()) as u16;
    let alloc_hint = pdu_data.len() as u32;
    let mut out = Vec::with_capacity(MSRPC_RESP_HEADER_SIZE + pdu_data.len());
    out.push(req_header.header.ver_major);
    out.push(req_header.header.ver_minor);
    out.push(PACKET_TYPE_RESPONSE);
    out.push(FLAG_FIRST_FRAG | FLAG_LAST_FRAG);
    out.extend_from_slice(&req_header.header.representation.to_le_bytes());
    out.extend_from_slice(&frag_len.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes()); // auth_len = 0
    out.extend_from_slice(&req_header.header.call_id.to_le_bytes());
    out.extend_from_slice(&alloc_hint.to_le_bytes());
    out.extend_from_slice(&req_header.ctx_id.to_le_bytes());
    out.push(0); // cancel_count
    out.push(0); // padding
    out.extend_from_slice(pdu_data);
    out
}

// ---------- BindRequest ----------

#[derive(Debug, Clone)]
pub struct BindRequest {
    pub max_tfrag: u16,
    pub max_rfrag: u16,
    pub assoc_group: u32,
    pub ctx_num: u8,
    pub reserved: u8,
    pub reserved2: u16,
    pub ctx_items: Vec<CtxItem>,
}

#[derive(Debug, Clone, Copy)]
pub struct CtxItem {
    pub context_id: u16,
    pub trans_items: u8,
    pub pad: u8,
    pub abstract_syntax_uuid: [u8; 16],
    pub abstract_syntax_ver: u32,
    pub transfer_syntax_uuid: [u8; 16],
    pub transfer_syntax_ver: u32,
}

impl CtxItem {
    pub fn marshal(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.context_id.to_le_bytes());
        out.push(self.trans_items);
        out.push(self.pad);
        out.extend_from_slice(&self.abstract_syntax_uuid);
        out.extend_from_slice(&self.abstract_syntax_ver.to_le_bytes());
        out.extend_from_slice(&self.transfer_syntax_uuid);
        out.extend_from_slice(&self.transfer_syntax_ver.to_le_bytes());
    }
}

pub fn parse_bind_request(data: &[u8]) -> Result<BindRequest, RpcError> {
    if data.len() < 12 {
        return Err(RpcError::TooShort("data too short for BIND request".into()));
    }
    let max_tfrag = u16::from_le_bytes([data[0], data[1]]);
    let max_rfrag = u16::from_le_bytes([data[2], data[3]]);
    let assoc_group = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
    let ctx_num = data[8];
    let reserved = data[9];
    let reserved2 = u16::from_le_bytes([data[10], data[11]]);
    let mut offset = 12usize;
    let mut ctx_items = Vec::with_capacity(ctx_num as usize);
    for i in 0..(ctx_num as usize) {
        if offset + CTX_ITEM_SIZE > data.len() {
            return Err(RpcError::TooShort(format!(
                "data too short for context item {}",
                i
            )));
        }
        let s = &data[offset..offset + CTX_ITEM_SIZE];
        let mut abs_uuid = [0u8; 16];
        abs_uuid.copy_from_slice(&s[4..20]);
        let mut trans_uuid = [0u8; 16];
        trans_uuid.copy_from_slice(&s[24..40]);
        ctx_items.push(CtxItem {
            context_id: u16::from_le_bytes([s[0], s[1]]),
            trans_items: s[2],
            pad: s[3],
            abstract_syntax_uuid: abs_uuid,
            abstract_syntax_ver: u32::from_le_bytes([s[20], s[21], s[22], s[23]]),
            transfer_syntax_uuid: trans_uuid,
            transfer_syntax_ver: u32::from_le_bytes([s[40], s[41], s[42], s[43]]),
        });
        offset += CTX_ITEM_SIZE;
    }
    Ok(BindRequest {
        max_tfrag,
        max_rfrag,
        assoc_group,
        ctx_num,
        reserved,
        reserved2,
        ctx_items,
    })
}

// ---------- BIND ACK ----------

pub fn build_bind_ack_response(req_data: &[u8], port: u16, call_id: u32) -> Result<Vec<u8>, RpcError> {
    let header = MsRpcHeader::parse(req_data)?;
    let pdu = pdu_data(req_data).ok_or_else(|| RpcError::TooShort("missing bind pdu".into()))?;
    let bind = parse_bind_request(pdu)?;

    let port_str = port.to_string();
    let secondary_addr_len = (port_str.len() + 1) as u16;
    let pad = (4 - ((secondary_addr_len as usize + 26) % 4)) % 4;

    let mut ctx_results = vec![0u8; bind.ctx_num as usize * CTX_ITEM_RESULT_SIZE];
    for i in 0..(bind.ctx_num as usize) {
        let ts = bind.ctx_items[i].transfer_syntax_uuid;
        let (result, reason, ts_out, ver_out) = if ts == UUID_NDR32 {
            (CONT_RESULT_ACCEPT, 0u16, UUID_NDR32, 2u32)
        } else if ts == UUID_TIME {
            (3u16, 3u16, UUID_EMPTY, 0u32)
        } else {
            (CONT_RESULT_PROV_REJECT, CONT_RESULT_PROV_REJECT, UUID_EMPTY, 0u32)
        };
        let o = i * CTX_ITEM_RESULT_SIZE;
        ctx_results[o..o + 2].copy_from_slice(&result.to_le_bytes());
        ctx_results[o + 2..o + 4].copy_from_slice(&reason.to_le_bytes());
        ctx_results[o + 4..o + 20].copy_from_slice(&ts_out);
        ctx_results[o + 20..o + 24].copy_from_slice(&ver_out.to_le_bytes());
    }

    let frag_len = 26 + secondary_addr_len as usize + pad + 4 + ctx_results.len();
    let mut resp = Vec::with_capacity(frag_len);
    resp.push(header.ver_major);
    resp.push(header.ver_minor);
    resp.push(PACKET_TYPE_BIND_ACK);
    resp.push(FLAG_FIRST_FRAG | FLAG_LAST_FRAG | FLAG_CONC_MPX);
    resp.extend_from_slice(&header.representation.to_le_bytes());
    resp.extend_from_slice(&(frag_len as u16).to_le_bytes());
    resp.extend_from_slice(&header.auth_len.to_le_bytes());
    resp.extend_from_slice(&call_id.to_le_bytes());
    resp.extend_from_slice(&bind.max_tfrag.to_le_bytes());
    resp.extend_from_slice(&bind.max_rfrag.to_le_bytes());
    resp.extend_from_slice(&0x1063bf3fu32.to_le_bytes());
    resp.extend_from_slice(&secondary_addr_len.to_le_bytes());
    resp.extend_from_slice(port_str.as_bytes());
    resp.push(0); // null terminator
    for _ in 0..pad {
        resp.push(0);
    }
    resp.push(bind.ctx_num);
    resp.push(0); // Reserved
    resp.extend_from_slice(&0u16.to_le_bytes()); // Reserved2
    resp.extend_from_slice(&ctx_results);
    Ok(resp)
}

// ---------- BIND request (client side) ----------

pub fn build_bind_request(call_id: u32) -> Vec<u8> {
    let first_ctx = CtxItem {
        context_id: 0,
        trans_items: 1,
        pad: 0,
        abstract_syntax_uuid: KMS_INTERFACE_UUID,
        abstract_syntax_ver: 1,
        transfer_syntax_uuid: UUID_NDR32,
        transfer_syntax_ver: 2,
    };
    let second_ctx = CtxItem {
        context_id: 1,
        trans_items: 1,
        pad: 0,
        abstract_syntax_uuid: KMS_INTERFACE_UUID,
        abstract_syntax_ver: 1,
        transfer_syntax_uuid: UUID_TIME,
        transfer_syntax_ver: 1,
    };

    let mut body = Vec::with_capacity(12 + 2 * CTX_ITEM_SIZE);
    body.extend_from_slice(&5840u16.to_le_bytes());
    body.extend_from_slice(&5840u16.to_le_bytes());
    body.extend_from_slice(&0u32.to_le_bytes()); // assoc_group
    body.push(2); // ctx_num
    body.push(0); // Reserved
    body.extend_from_slice(&0u16.to_le_bytes()); // Reserved2
    first_ctx.marshal(&mut body);
    second_ctx.marshal(&mut body);

    let header = MsRpcHeader {
        ver_major: 5,
        ver_minor: 0,
        typ: PACKET_TYPE_BIND,
        flags: FLAG_FIRST_FRAG | FLAG_LAST_FRAG | FLAG_CONC_MPX,
        representation: 0x10,
        frag_len: (MSRPC_HEADER_SIZE + body.len()) as u16,
        auth_len: 0,
        call_id,
    };
    let mut out = Vec::with_capacity(header.frag_len as usize);
    out.extend_from_slice(&header.marshal());
    out.extend_from_slice(&body);
    out
}

// ---------- Build RPC REQUEST (client wrapping KMS data) ----------

pub fn build_rpc_request(kms_data: &[u8], call_id: u32) -> Vec<u8> {
    let frag_len = (MSRPC_REQUEST_HEADER_SIZE + kms_data.len()) as u16;
    let header = MsRpcHeader {
        ver_major: 5,
        ver_minor: 0,
        typ: PACKET_TYPE_REQUEST,
        flags: FLAG_FIRST_FRAG | FLAG_LAST_FRAG,
        representation: 0x10,
        frag_len,
        auth_len: 0,
        call_id,
    };
    let mut out = Vec::with_capacity(frag_len as usize);
    out.extend_from_slice(&header.marshal());
    out.extend_from_slice(&(kms_data.len() as u32).to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes()); // ctx_id = 0
    out.extend_from_slice(&0u16.to_le_bytes()); // op_num = 0
    out.extend_from_slice(kms_data);
    out
}

// ---------- Async recv (tokio AsyncRead) ----------

pub async fn recv_all<R: AsyncRead + Unpin>(
    reader: &mut R,
    max_frag_len: u16,
) -> Result<Vec<u8>, RpcError> {
    let mut buf = vec![0u8; max_frag_len as usize];
    let n = recv_all_into(reader, &mut buf, max_frag_len).await?;
    Ok(buf[..n].to_vec())
}

pub async fn recv_all_into<R: AsyncRead + Unpin>(
    reader: &mut R,
    buf: &mut [u8],
    max_frag_len: u16,
) -> Result<usize, RpcError> {
    if buf.len() < MSRPC_HEADER_SIZE {
        return Err(RpcError::TooShort("buffer smaller than header".into()));
    }
    reader.read_exact(&mut buf[..MSRPC_HEADER_SIZE]).await?;
    let frag_len = u16::from_le_bytes([buf[8], buf[9]]);
    if frag_len > max_frag_len {
        return Err(RpcError::TooShort(format!(
            "fragment length {} exceeds maximum allowed {}",
            frag_len, max_frag_len
        )));
    }
    if (frag_len as usize) <= MSRPC_HEADER_SIZE {
        return Ok(MSRPC_HEADER_SIZE);
    }
    reader
        .read_exact(&mut buf[MSRPC_HEADER_SIZE..frag_len as usize])
        .await?;
    Ok(frag_len as usize)
}
