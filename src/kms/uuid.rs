// KMS UUID type — wire format is bytes_le (Windows GUID): the first three groups in the
// canonical "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" string are encoded little-endian, the
// last two groups are big-endian. Storage is the bytes_le form (i.e. as it appears on wire).

const HEXTABLE: &[u8] = b"0123456789abcdef";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct KmsUuid(pub [u8; 16]);

impl KmsUuid {
    pub const fn from_bytes(b: [u8; 16]) -> Self {
        Self(b)
    }

    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    pub fn random() -> Self {
        use rand::RngCore;
        let mut b = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut b);
        Self(b)
    }

    /// Parse a 32-hex-char or 36-char (with dashes) UUID string into bytes_le format.
    pub fn parse(s: &str) -> Result<Self, String> {
        if s.len() != 36 && s.len() != 32 {
            return Err(format!("invalid UUID string length: {}", s.len()));
        }
        let bytes_in = s.as_bytes();
        let mut nibbles = [0u8; 16];
        let mut j = 0usize;
        let mut i = 0usize;
        while i < bytes_in.len() {
            let c = bytes_in[i];
            if c == b'-' {
                i += 1;
                continue;
            }
            if i + 1 >= bytes_in.len() {
                return Err("invalid UUID string".into());
            }
            let hi = hex_val(c).ok_or("invalid hex character in UUID")?;
            let lo = hex_val(bytes_in[i + 1]).ok_or("invalid hex character in UUID")?;
            if j >= 16 {
                return Err("invalid UUID string".into());
            }
            nibbles[j] = (hi << 4) | lo;
            j += 1;
            i += 2;
        }
        if j != 16 {
            return Err("invalid UUID string".into());
        }
        // bytes_le: first three groups stored little-endian.
        let mut u = [0u8; 16];
        u[0] = nibbles[3];
        u[1] = nibbles[2];
        u[2] = nibbles[1];
        u[3] = nibbles[0];
        u[4] = nibbles[5];
        u[5] = nibbles[4];
        u[6] = nibbles[7];
        u[7] = nibbles[6];
        u[8..16].copy_from_slice(&nibbles[8..16]);
        Ok(Self(u))
    }

    /// Format as canonical UUID string (8-4-4-4-12) using bytes_le → standard transform.
    pub fn to_string(&self) -> String {
        let u = &self.0;
        let mut buf = [0u8; 36];

        // Group 1: bytes 0-3 (LE)
        let v32 = u32::from_le_bytes([u[0], u[1], u[2], u[3]]);
        write_u32_hex(v32, &mut buf[0..8]);
        buf[8] = b'-';
        // Group 2: bytes 4-5 (LE)
        let v16 = u16::from_le_bytes([u[4], u[5]]);
        write_u16_hex(v16, &mut buf[9..13]);
        buf[13] = b'-';
        // Group 3: bytes 6-7 (LE)
        let v16 = u16::from_le_bytes([u[6], u[7]]);
        write_u16_hex(v16, &mut buf[14..18]);
        buf[18] = b'-';
        // Group 4: bytes 8-9 (BE)
        for i in 0..2 {
            let b = u[8 + i];
            buf[19 + i * 2] = HEXTABLE[(b >> 4) as usize];
            buf[20 + i * 2] = HEXTABLE[(b & 0xf) as usize];
        }
        buf[23] = b'-';
        // Group 5: bytes 10-15 (BE)
        for i in 0..6 {
            let b = u[10 + i];
            buf[24 + i * 2] = HEXTABLE[(b >> 4) as usize];
            buf[25 + i * 2] = HEXTABLE[(b & 0xf) as usize];
        }
        std::str::from_utf8(&buf).unwrap().to_string()
    }
}

impl std::fmt::Display for KmsUuid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_string())
    }
}

fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

fn write_u32_hex(mut v: u32, buf: &mut [u8]) {
    for i in (0..8).rev() {
        buf[i] = HEXTABLE[(v & 0xf) as usize];
        v >>= 4;
    }
}

fn write_u16_hex(mut v: u16, buf: &mut [u8]) {
    for i in (0..4).rev() {
        buf[i] = HEXTABLE[(v & 0xf) as usize];
        v >>= 4;
    }
}

pub fn must_uuid(s: &str) -> KmsUuid {
    KmsUuid::parse(s).expect("invalid UUID string")
}
