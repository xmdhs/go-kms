// UTF-16LE encoding/decoding helpers matching Go's `encoding/utf16` + binary.LittleEndian usage.

pub fn encode_utf16le(s: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len() * 2);
    for u in s.encode_utf16() {
        out.extend_from_slice(&u.to_le_bytes());
    }
    out
}

/// Mirrors Go's DecodeUTF16LE: trims trailing odd byte, strips trailing U+0000 code units, decodes.
pub fn decode_utf16le(b: &[u8]) -> String {
    let mut bytes: &[u8] = if b.len() % 2 != 0 { &b[..b.len() - 1] } else { b };
    // Drop trailing null code units.
    while bytes.len() >= 2 {
        let last_idx = bytes.len() - 2;
        if bytes[last_idx] == 0 && bytes[last_idx + 1] == 0 {
            bytes = &bytes[..last_idx];
        } else {
            break;
        }
    }
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    String::from_utf16_lossy(&units)
}
