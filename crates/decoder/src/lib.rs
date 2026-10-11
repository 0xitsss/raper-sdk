//! Intent decoder for 0x251fb27d meta-txs (Papertrade, HyperEVM 999).
//!
//! Subcalls are tightly PACKED (not word-aligned): each anchor selector is
//! followed immediately by its params. Open leg has 11 words, close legs 7.
//!
//! Anchor status:
//! - 0xec6783f0 — CONFIRMED open leg (user, instrument, margin, leverage, deadline, side)
//! - 0x2792e706 — close-variant A (params unmapped, same 7-word shape)
//! - 0x8d09f23f — close-variant B (params unmapped, same 7-word shape)

pub const ENTRY: &str = "251fb27d";

/// Parsed open leg: (user, instrument, ?, margin_raw, leverage, ?, ?, deadline, ?, ?, ?).
/// NOTE: side field is UNCONFIRMED (candidates: w2 which is 0/1 in traces,
/// or w8 which reads 27/28 — possibly sig-related, not side). Do not trust
/// either without cross-check against tape.
#[derive(Debug, Default, PartialEq)]
pub struct OpenParams {
    pub user: String,
    pub instrument: u32,
    pub margin_raw: u128,
    pub leverage: u32,
    pub deadline: u64,
    pub w2: u128,
    pub w8: u128,
}

/// Close leg params: 7 opaque words (f0..f6), unmapped.
#[derive(Debug, Default, PartialEq)]
pub struct CloseParams {
    pub anchor: &'static str,
    pub f0_user: String,
    pub words: [String; 7],
}

#[derive(Debug, PartialEq)]
pub enum Leg {
    Open(OpenParams),
    Close { anchor: &'static str, params: CloseParams },
    Unknown { reason: &'static str },
}

fn hex_bytes(h: &str) -> Vec<u8> {
    let h = h.strip_prefix("0x").unwrap_or(h);
    let b = h.as_bytes();
    let hv = |c: u8| match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        b'A'..=b'F' => c - b'A' + 10,
        _ => 0,
    };
    let mut out = Vec::with_capacity(b.len() / 2);
    let mut i = 0;
    while i + 1 < b.len() {
        out.push(hv(b[i]) << 4 | hv(b[i + 1]));
        i += 2;
    }
    out
}

fn w128(w: &[u8]) -> u128 {
    let mut a = [0u8; 16];
    a.copy_from_slice(&w[16..32]);
    u128::from_be_bytes(a)
}

fn waddr(w: &[u8]) -> String {
    format!("0x{}", hex_str(&w[12..]))
}

fn hex_str(b: &[u8]) -> String {
    const H: &[u8] = b"0123456789abcdef";
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        s.push(H[(x >> 4) as usize] as char);
        s.push(H[(x & 15) as usize] as char);
    }
    s
}

fn find(bytes: &[u8], sig: [u8; 4]) -> Option<usize> {
    bytes.windows(4).position(|w| w == sig)
}

/// Classify first recognizable leg by anchor priority: open, then closes.
pub fn classify(calldata_hex: &str) -> Leg {
    let bytes = hex_bytes(calldata_hex);
    if bytes.len() < 4 {
        return Leg::Unknown { reason: "short" };
    }
    if let Some(pos) = find(&bytes, [0xec, 0x67, 0x83, 0xf0]) {
        match parse_open_at(&bytes, pos) {
            Some(o) => return Leg::Open(o),
            None => return Leg::Unknown { reason: "short" },
        }
    }
    for (anchor, sig) in [("2792e706", [0x27, 0x92, 0xe7, 0x06]), ("8d09f23f", [0x8d, 0x09, 0xf2, 0x3f])] {
        if let Some(pos) = find(&bytes, sig) {
            match parse_close_at(&bytes, pos, anchor) {
                Some(p) => return Leg::Close { anchor, params: p },
                None => return Leg::Unknown { reason: "short" },
            }
        }
    }
    Leg::Unknown { reason: "no-anchor" }
}

fn parse_open_at(bytes: &[u8], pos: usize) -> Option<OpenParams> {
    let p = bytes.get(pos + 4..pos + 4 + 352)?;
    let w = |i: usize| &p[i * 32..(i + 1) * 32];
    Some(OpenParams {
        user: waddr(w(0)),
        instrument: w128(w(1)) as u32,
        margin_raw: w128(w(3)),
        leverage: w128(w(4)) as u32,
        deadline: w128(w(7)) as u64,
        w2: w128(w(2)),
        w8: w128(w(8)),
    })
}

fn parse_close_at(bytes: &[u8], pos: usize, anchor: &'static str) -> Option<CloseParams> {
    let p = bytes.get(pos + 4..pos + 4 + 224)?;
    let mut words = core::array::from_fn(|_| String::new());
    for (i, w) in words.iter_mut().enumerate() {
        *w = hex_str(&p[i * 32..(i + 1) * 32]);
    }
    Some(CloseParams { anchor, f0_user: waddr(&p[..32]), words })
}

/// One-line describe for unknown-log.
pub fn describe_hex(calldata_hex: &str) -> String {
    let bytes = hex_bytes(calldata_hex);
    let mut anchors = vec![];
    for (name, sig) in [("ec6783f0", [0xec, 0x67, 0x83, 0xf0]), ("2792e706", [0x27, 0x92, 0xe7, 0x06]), ("8d09f23f", [0x8d, 0x09, 0xf2, 0x3f])] {
        if find(&bytes, sig).is_some() {
            anchors.push(name);
        }
    }
    let head = hex_str(&bytes[..bytes.len().min(64)]);
    format!("bytes={} anchors=[{}] head={}", bytes.len(), anchors.join(","), head)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn packed_open() -> String {
        let mut h = String::from("251fb27d");
        h.push_str(&"00".repeat(60));
        h.push_str("00000164");
        h.push_str("ec6783f0");
        let params = [
            "0000000000000000000000001111111111111111111111111111111111111111",
            "0000000000000000000000000000000000000000000000000000000000000001",
            "0000000000000000000000000000000000000000000000000000000000000001",
            "0000000000000000000000000000000000000000000000000000000000000064",
            "00000000000000000000000000000000000000000000000000000000000003e8",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "0000000000000000000000000000000000000000000000000000000069183d00",
            "000000000000000000000000000000000000000000000000000000000000001c",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "0000000000000000000000000000000000000000000000000000000000000000",
        ];
        for p in params {
            h.push_str(p);
        }
        "0x".to_string() + &h
    }

    #[test]
    fn open_packed() {
        match classify(&packed_open()) {
            Leg::Open(o) => {
                assert_eq!(o.instrument, 1);
                assert_eq!(o.margin_raw, 0x64);
                assert_eq!(o.leverage, 1000);
                assert_eq!(o.user, "0x1111111111111111111111111111111111111111");
            }
            other => panic!("expected Open, got {:?}", other),
        }
    }

    #[test]
    fn close_legs() {
        for anchor in ["2792e706", "8d09f23f"] {
            let h = String::from("251fb27d") + &"00".repeat(60) + "000000e4" + anchor + &"ab".repeat(224);
            match classify(&("0x".to_string() + &h)) {
                Leg::Close { anchor: a, params } => {
                    assert_eq!(a, anchor);
                    assert_eq!(params.words.len(), 7);
                }
                other => panic!("expected Close, got {:?}", other),
            }
        }
    }

    #[test]
    fn unknown_branches() {
        assert_eq!(classify("0x"), Leg::Unknown { reason: "short" });
        assert_eq!(classify("0x251fb27d"), Leg::Unknown { reason: "no-anchor" });
        assert_eq!(classify("0x251fb27d00000164ec6783f0"), Leg::Unknown { reason: "short" });
    }

    #[test]
    fn describe_works() {
        let d = describe_hex(&packed_open());
        assert!(d.contains("bytes=") && d.contains("ec6783f0"));
    }
}
