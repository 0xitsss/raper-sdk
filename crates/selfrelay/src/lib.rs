//! Builder for the Papertrade wallet meta-tx `0x251fb27d` (HyperEVM 999).
//!
//! Encoding only. Nothing here signs with a key or sends a transaction:
//! the caller supplies the ECDSA `(r, s, v)` obtained elsewhere.
//!
//! ## Reverse-engineered layout (live-trace hypothesis)
//!
//! A signed call with a single intent and a single open-leg subcall
//! (`0xec6783f0` + 11 param words = 356 bytes of subcall data) is
//! **676 bytes = 4-byte selector + 21 ABI words**:
//!
//! ```text
//! [0..4]    selector 0x251fb27d
//! w0        U256(0x20)              # offset to intents array
//! w1        U256(0x01)              # intents count = 1
//! w2        U256(0x20)              # offset to element 0
//! w3        address word(target)    # Exchange proxy
//! w4        U256(data_len)          # total subcall DATA bytes (excl. prefixes);
//!                                   # 356 = 0x164 for one open leg
//! w5..w16   blob, zero-padded to 32 B:
//!             concat over subcalls of [u32BE(len_i) || data_i]
//!             (per-call 4-byte len prefix, then selector + params tightly)
//! w17       U256(deadline)          # unix seconds, ~now on live traces
//! w18       U256(r)
//! w19       U256(s)
//! w20       U256(v)                 # 27 / 28 (0x1b / 0x1c); last calldata byte = v
//! ```
//!
//! Notes on the raw first chunk: bytes `[0..32]` read as
//! `251fb27d` + 28 zero bytes, because the top 28 bytes of `w0 = 0x20`
//! are zero. "w1 = 0x20, w2 = 0x01, w3 = 0x20" in the trace notes is
//! 1-based word numbering for `w0..w2` above; `w4 = target` and the tail
//! deadline at 0-based word index 17 ([`DEADLINE_WORD_INDEX`]).
//!
//! ## Auth model (VERIFIED in wallet decompile, no ecrecover on-chain)
//!
//! - No `ecrecover` exists in wallet or Exchange bytecode: signatures are
//!   verified OFF-CHAIN by the official relayer. On-chain auth is:
//!   caller bitmap (`only authorized relayers/session keys`) + selector
//!   allowlist (`0xec6783f0` open, `0x83115825` second entry) + target
//!   allowlist (exchange / sessionKeyManager).
//! - To self-relay you need your EOA/session key authorized in the bitmap
//!   (owner-only `0x9011e5f9` or the registerSessionKey flow), NOT a magic
//!   preimage. `r/s/v` bytes ride along for the relayer path.
//!
//! ## What is NOT confirmed (do not rely on for mainnet)
//!
//! - **Relayer sig scheme.** [`intent_hash`] returns `keccak256` of the whole
//!   unsigned blob as a working hypothesis for what the relayer checks.
//!   Harmless for direct submit (chain does not check it), required only
//!   if you route via the official relayer.
//! - **Order-hash words.** Live traces show two hash-like `bytes32` right
//!   before the deadline. In this layout they are the trailing words of the
//!   subcall params region (reserved/zero slots on synthetic legs); their
//!   exact semantics are UNCONFIRMED and they are NOT separate builder
//!   inputs (cf. zero-filled unknown slots in `raper-sdk::tx::encode_open`).
//! - **`v` encoding.** The wire form used here is a full U256 word with value
//!   27/28, so the significant signature bytes are 32 + 32 + 1 = 65 and the
//!   last calldata byte is `v`. Whether the contract accepts EIP-155
//!   chain-id-shifted `v` (HyperEVM 999) is UNCONFIRMED; the live example
//!   shows raw `v = 0x1b = 27`.
//! - **Single-intent only.** `w1` is fixed to `0x01`; multi-intent batching
//!   is not implemented.
//!
//! ## Wiring note
//!
//! This crate is intentionally detached from the parent workspace
//! (`[workspace]` below) so the workspace `members` list stays untouched.
//! To build it as a workspace member, add `"crates/selfrelay"` to
//! `v2/Cargo.toml` members explicitly.

use sha3::{Digest, Keccak256};

/// Meta-tx entry selector on the wallet logic (see
/// `crates/raper-sdk/src/addresses.rs`: `SEL_META_TX`).
pub const SEL_META_TX: [u8; 4] = [0x25, 0x1f, 0xb2, 0x7d];
/// Same selector as lowercase hex (no `0x` prefix).
pub const SEL_META_TX_HEX: &str = "251fb27d";
/// Open-leg subcall anchor (see `addresses.rs`: `SEL_OPEN`).
pub const SEL_OPEN: [u8; 4] = [0xec, 0x67, 0x83, 0xf0];

/// 0-based word index (after the selector) of the tail deadline for the
/// canonical single-open-leg vector (12 padded blob words).
pub const DEADLINE_WORD_INDEX: usize = 17;
/// Canonical signed length for one open leg: 4 + 21 * 32 = 676.
pub const SIGNED_LEN_OPEN_LEG: usize = 676;
/// Canonical unsigned length for one open leg: 4 + 18 * 32 = 580.
pub const UNSIGNED_LEN_OPEN_LEG: usize = 580;
/// Open-leg subcall data length: 4 (anchor) + 11 * 32 (params) = 356 = 0x164.
pub const OPEN_SUBCALL_DATA_LEN: usize = 356;
/// Close-leg subcall data length: 4 (anchor) + 7 * 32 (params) = 228 = 0xe4.
pub const CLOSE_SUBCALL_DATA_LEN: usize = 228;

/// Intent to be relayed through the wallet meta-tx entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Intent {
    /// Hex address (`0x` + 40 hex chars), normally the Exchange proxy.
    pub target: String,
    /// Opaque subcalls (each already includes its 4-byte anchor selector).
    pub subcalls: Vec<Vec<u8>>,
    /// Unix timestamp (seconds) for the tail deadline word.
    pub deadline: u64,
}

/// Builder failure modes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// `subcalls` is empty (nothing to relay).
    EmptySubcalls,
    /// Subcall `index` is empty (a zero-length call is ambiguous on the wire).
    EmptySubcall(usize),
    /// `target` is not a `0x`-prefixed 40-hex-char address.
    BadAddress(String),
    /// Subcall `index` exceeds the 4-byte length prefix range.
    SubcallTooLarge(usize),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::EmptySubcalls => write!(f, "selfrelay: no subcalls"),
            Error::EmptySubcall(i) => write!(f, "selfrelay: subcall {i} is empty"),
            Error::BadAddress(a) => write!(f, "selfrelay: bad address {a}"),
            Error::SubcallTooLarge(i) => write!(f, "selfrelay: subcall {i} exceeds u32 length"),
        }
    }
}

impl std::error::Error for Error {}

/// Fallible result of the builder (the task shorthand `-> Vec<u8>` omits the
/// error channel; empty input must fail, so the channel is required).
pub type Result<T> = std::result::Result<T, Error>;

fn u256_word(v: u128) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[16..].copy_from_slice(&v.to_be_bytes());
    w
}

fn u256_word_u64(v: u64) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[24..].copy_from_slice(&v.to_be_bytes());
    w
}

fn target_bytes(target: &str) -> std::result::Result<Vec<u8>, Error> {
    let h = target.strip_prefix("0x").unwrap_or(target);
    if h.len() != 40 || !h.bytes().all(|c| c.is_ascii_hexdigit()) {
        return Err(Error::BadAddress(target.to_string()));
    }
    hex::decode(h).map_err(|_| Error::BadAddress(target.to_string()))
}

fn addr_word(target: &str) -> std::result::Result<[u8; 32], Error> {
    let h = target.strip_prefix("0x").unwrap_or(target);
    if h.len() != 40 || !h.bytes().all(|c| c.is_ascii_hexdigit()) {
        return Err(Error::BadAddress(target.to_string()));
    }
    let raw = hex::decode(h).map_err(|_| Error::BadAddress(target.to_string()))?;
    let mut w = [0u8; 32];
    w[12..].copy_from_slice(&raw);
    Ok(w)
}

fn checked_parts(intent: &Intent) -> Result<(usize, Vec<u8>)> {
    if intent.subcalls.is_empty() {
        return Err(Error::EmptySubcalls);
    }
    let mut data_len: usize = 0;
    let mut blob = Vec::new();
    for (i, sc) in intent.subcalls.iter().enumerate() {
        if sc.is_empty() {
            return Err(Error::EmptySubcall(i));
        }
        if sc.len() > u32::MAX as usize {
            return Err(Error::SubcallTooLarge(i));
        }
        data_len += sc.len();
        blob.extend_from_slice(&(sc.len() as u32).to_be_bytes());
        blob.extend_from_slice(sc);
    }
    Ok((data_len, blob))
}

/// Unsigned calldata: everything except the `(r, s, v)` tail words.
pub fn encode_unsigned(intent: &Intent) -> Result<Vec<u8>> {
    let target = addr_word(&intent.target)?;
    let (data_len, blob) = checked_parts(intent)?;
    let pad = (32 - blob.len() % 32) % 32;

    let mut out = Vec::with_capacity(4 + 28 + 6 * 32 + blob.len() + pad);
    out.extend_from_slice(&SEL_META_TX);
    out.extend_from_slice(&[0u8; 28]);
    out.extend_from_slice(&u256_word(0x20));
    out.extend_from_slice(&u256_word(0x01));
    out.extend_from_slice(&u256_word(0x20));
    out.extend_from_slice(&target_bytes(&intent.target)?);
    // Live layout: 0xa0, 0x01, aux1(32B), aux2(32B), then blob.
    // aux content unverified (zeros here) — HYPOTHESIS.
    out.extend_from_slice(&u256_word(0xa0));
    out.extend_from_slice(&u256_word(0x01));
    out.extend_from_slice(&[0u8; 32]);
    out.extend_from_slice(&[0u8; 32]);
    out.extend_from_slice(&(data_len as u32).to_be_bytes());
    out.extend_from_slice(&blob);
    out.resize(out.len() + pad, 0);
    out.extend_from_slice(&u256_word_u64(intent.deadline));
    Ok(out)
}

/// Signed calldata: unsigned blob + `U256(r) + U256(s) + U256(v)` tail words.
pub fn encode_signed(intent: &Intent, r: &[u8; 32], s: &[u8; 32], v: u8) -> Result<Vec<u8>> {
    let mut out = encode_unsigned(intent)?;
    out.extend_from_slice(r);
    out.extend_from_slice(s);
    out.extend_from_slice(&u256_word(v as u128));
    Ok(out)
}

/// AUTH MODEL (verified in wallet decompile): on-chain auth is caller bitmap + selector allowlist; is `keccak256` of the whole unsigned
/// blob. EIP-712 typed-data vs raw-hash is NOT confirmed; neither is the
/// exact preimage. Verify against a live signed trace before mainnet use.
pub fn intent_hash(unsigned: &[u8]) -> [u8; 32] {
    let mut h = Keccak256::new();
    h.update(unsigned);
    h.finalize().into()
}

/// Read back the tail deadline word of an unsigned blob (last word).
pub fn decode_deadline_unsigned(unsigned: &[u8]) -> Option<u64> {
    let w = unsigned.get(unsigned.len().checked_sub(32)?..)?;
    let mut a = [0u8; 8];
    a.copy_from_slice(&w[24..]);
    Some(u64::from_be_bytes(a))
}

/// Read back the tail deadline word of a signed blob (word before the
/// trailing 96-byte `r/s/v` tail).
pub fn decode_deadline_signed(signed: &[u8]) -> Option<u64> {
    let end = signed.len().checked_sub(96)?;
    let w = signed.get(end.checked_sub(32)?..end)?;
    let mut a = [0u8; 8];
    a.copy_from_slice(&w[24..]);
    Some(u64::from_be_bytes(a))
}

/// Read back the `w3` target word of an unsigned or signed blob.
pub fn decode_target(calldata: &[u8]) -> Option<String> {
    let w = calldata.get(4 + 3 * 32..4 + 4 * 32)?;
    Some(format!("0x{}", hex::encode(&w[12..])))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Protocol constant copied from crates/raper-sdk/src/addresses.rs
    // (`EXCHANGE`, HyperEVM 999). No other real addresses are used.
    const EXCHANGE: &str = "0x6cd5661646289fb6e65ea5c032310fded797d0a2";
    const USER_SYNTH: &str = "0x1111111111111111111111111111111111111111";
    const DEADLINE: u64 = 0x6acb50de; // example unix-time-shaped value from trace notes

    fn word_at(calldata: &[u8], index: usize) -> &[u8] {
        &calldata[4 + index * 32..4 + (index + 1) * 32]
    }

    fn word_val(word: &[u8]) -> u128 {
        let mut a = [0u8; 16];
        a.copy_from_slice(&word[16..]);
        u128::from_be_bytes(a)
    }

    /// Synthetic open leg mirroring raper-sdk tx::encode_open slot order:
    /// anchor + (user, instrument, 0, margin, leverage, 0, 0, deadline, side, 0, 0).
    fn synth_open(deadline: u64) -> Vec<u8> {
        let mut sc = Vec::with_capacity(4 + 11 * 32);
        sc.extend_from_slice(&SEL_OPEN);
        let user = hex::decode(USER_SYNTH.trim_start_matches("0x")).unwrap();
        let mut uw = [0u8; 32];
        uw[12..].copy_from_slice(&user);
        sc.extend_from_slice(&uw);
        for v in [
            1u128, // instrument = ETH
            0,
            2000, // margin_raw
            500,  // leverage
            0,
            0,
            deadline as u128,
            28, // side/sig-ish slot (synthetic)
            0,
            0,
        ] {
            sc.extend_from_slice(&u256_word(v));
        }
        sc
    }

    fn synth_close(anchor: [u8; 4]) -> Vec<u8> {
        let mut sc = Vec::with_capacity(4 + 7 * 32);
        sc.extend_from_slice(&anchor);
        for i in 0..7u128 {
            sc.extend_from_slice(&u256_word(0xabc0 + i));
        }
        sc
    }

    #[test]
    fn canonical_open_shape_live_layout() {
        let intent = Intent {
            target: EXCHANGE.to_string(),
            subcalls: vec![synth_open(DEADLINE)],
            deadline: DEADLINE,
        };
        let unsigned = encode_unsigned(&intent).unwrap();
        let signed = encode_signed(&intent, &[0x11; 32], &[0x22; 32], 0x1b).unwrap();
        // live: signed 676 B, unsigned 580 B
        assert_eq!(signed.len(), SIGNED_LEN_OPEN_LEG);
        assert_eq!(unsigned.len(), UNSIGNED_LEN_OPEN_LEG);
        // head: sel | pad28 | 0x20 | 0x01
        assert_eq!(&signed[..4], &SEL_META_TX);
        assert!(signed[4..32].iter().all(|b| *b == 0));
        assert_eq!(word_val(&signed[32..64]), 0x20);
        assert_eq!(word_val(&signed[64..96]), 0x01);
        // target packed at bytes 128..148
        assert_eq!(hex::encode(&signed[128..148]).to_lowercase(), EXCHANGE.trim_start_matches("0x").to_lowercase());
        // blob at byte 276: u32 len + selector
        let blob_off = 276usize;
        let prefix = u32::from_be_bytes(signed[blob_off..blob_off + 4].try_into().unwrap());
        assert_eq!(prefix as usize, OPEN_SUBCALL_DATA_LEN);
        assert_eq!(&signed[blob_off + 4..blob_off + 8], &SEL_OPEN);
        // deadline = last word of unsigned
        assert_eq!(decode_deadline_unsigned(&unsigned).unwrap(), DEADLINE);
        assert_eq!(decode_deadline_signed(&signed).unwrap(), DEADLINE);
        // sig tail: r, s words; v last byte
        assert_eq!(&signed[signed.len() - 96..signed.len() - 64], &[0x11; 32]);
        assert_eq!(&signed[signed.len() - 64..signed.len() - 32], &[0x22; 32]);
        assert_eq!(signed[signed.len() - 1], 0x1b);
    }

    #[test]
fn encoding_is_deterministic_and_hash_sensitive() {
        let intent = Intent {
            target: EXCHANGE.to_string(),
            subcalls: vec![synth_open(DEADLINE)],
            deadline: DEADLINE,
        };
        let a = encode_unsigned(&intent).unwrap();
        let b = encode_unsigned(&intent).unwrap();
        assert_eq!(a, b);
        assert_eq!(intent_hash(&a), intent_hash(&b));

        let mut other = intent.clone();
        other.deadline = DEADLINE + 1;
        let c = encode_unsigned(&other).unwrap();
        assert_ne!(a, c);
        assert_ne!(intent_hash(&a), intent_hash(&c));
        assert_eq!(decode_deadline_unsigned(&c).unwrap(), DEADLINE + 1);
    }

    #[test]
    fn close_shaped_leg_prefix_is_0xe4() {
        let intent = Intent {
            target: EXCHANGE.to_string(),
            subcalls: vec![synth_close([0x27, 0x92, 0xe7, 0x06])],
            deadline: DEADLINE,
        };
        let signed = encode_signed(&intent, &[0x33; 32], &[0x44; 32], 28).unwrap();
        // blob = 4 + 224 = 228 padded to 256; unsigned = 4+160+256+32 = 452
        assert_eq!(signed.len(), 452 + 96);
        assert_eq!(
            word_val(word_at(&signed, 4)),
            CLOSE_SUBCALL_DATA_LEN as u128
        );
        let blob_off = 4 + 5 * 32;
        let prefix = u32::from_be_bytes(signed[blob_off..blob_off + 4].try_into().unwrap());
        assert_eq!(prefix as usize, CLOSE_SUBCALL_DATA_LEN);
        assert_eq!(prefix, 0xe4);
        assert_eq!(decode_deadline_signed(&signed).unwrap(), DEADLINE);
        assert_eq!(signed[signed.len() - 1], 28);
    }

    #[test]
    fn multiple_subcalls_concatenate_with_own_prefixes() {
        let a = synth_close([0x27, 0x92, 0xe7, 0x06]);
        let b = synth_close([0x8d, 0x09, 0xf2, 0x3f]);
        let intent = Intent {
            target: EXCHANGE.to_string(),
            subcalls: vec![a.clone(), b.clone()],
            deadline: DEADLINE,
        };
        let signed = encode_unsigned(&intent).unwrap();
        // w4 = total data length (prefixes excluded)
        assert_eq!(word_val(word_at(&signed, 4)), (a.len() + b.len()) as u128);
        let mut off = 4 + 5 * 32;
        for sc in [&a, &b] {
            let prefix = u32::from_be_bytes(signed[off..off + 4].try_into().unwrap());
            assert_eq!(prefix as usize, sc.len());
            assert_eq!(&signed[off + 4..off + 4 + sc.len()], sc.as_slice());
            off += 4 + sc.len();
        }
        assert_eq!(decode_deadline_unsigned(&signed).unwrap(), DEADLINE);
        // determinism across clone
        assert_eq!(signed, encode_unsigned(&intent).unwrap());
    }

    #[test]
    fn negative_empty_subcalls_is_error() {
        let empty = Intent {
            target: EXCHANGE.to_string(),
            subcalls: vec![],
            deadline: DEADLINE,
        };
        assert_eq!(encode_unsigned(&empty).unwrap_err(), Error::EmptySubcalls);
        assert_eq!(
            encode_signed(&empty, &[0u8; 32], &[0u8; 32], 27).unwrap_err(),
            Error::EmptySubcalls
        );
        let inner_empty = Intent {
            target: EXCHANGE.to_string(),
            subcalls: vec![vec![]],
            deadline: DEADLINE,
        };
        assert_eq!(
            encode_unsigned(&inner_empty).unwrap_err(),
            Error::EmptySubcall(0)
        );
        let bad_addr = Intent {
            target: "0x123".to_string(),
            subcalls: vec![synth_open(DEADLINE)],
            deadline: DEADLINE,
        };
        assert!(matches!(
            encode_unsigned(&bad_addr).unwrap_err(),
            Error::BadAddress(_)
        ));
    }
}

#[cfg(test)]
mod skeleton_tests {
    /// Live skeleton (HyperEVM tx eeba39…4d125f, 676 bytes): all fixed words
    /// must match our builder output. Addresses/aux/sig differ per tx.
    const W1: &str = "0000000000000000000000000000000000000000000000000000000000000020";
    const W2: &str = "0000000000000000000000000000000000000000000000000000000000000001";

    #[test]
    fn skeleton_words_match_live() {
        // Our builder must emit: sel | 0x20 | 0x01 | ... (first 3 words fixed)
        let intent = crate::Intent {
            target: "0x6cd5661646289fb6e65ea5c032310fded797d0a2".into(),
            subcalls: vec![vec![0xec, 0x67, 0x83, 0xf0]],
            deadline: 1791709406,
        };
        let unsigned = crate::encode_unsigned(&intent).expect("encode");
        assert_eq!(&unsigned[..4], &[0x25, 0x1f, 0xb2, 0x7d]);
        assert_eq!(&unsigned[4..36], &[0u8; 28]);
        assert_eq!(hex32(&unsigned[36..68]), W1);
        assert_eq!(hex32(&unsigned[68..100]), W2);
    }

    fn hex32(b: &[u8]) -> String {
        b.iter().map(|x| format!("{:02x}", x)).collect()
    }
}
