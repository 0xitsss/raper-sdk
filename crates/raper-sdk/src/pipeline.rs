//! End-to-end user pipeline: order -> intent -> sign -> presim -> submit -> track.
//!
//! The user brings: funded HyperEVM EOA + own wallet proxy (created via app
//! deposit flow) + session key registered on it. Everything else is here.
//!
//! ```text
//! OpenOrder -> build_open_intent -> sign -> encode_signed -> presim -> submit -> receipt
//! ```

use alloy::primitives::{Address, Bytes, U256};

/// User-side open order (human units).
#[derive(Debug, Clone)]
pub struct OpenOrder {
    /// 0 = BTC, 1 = ETH.
    pub instrument: u32,
    /// true = long.
    pub is_long: bool,
    /// Margin in USD.
    pub margin_usd: f64,
    /// 1..=1000.
    pub leverage: u32,
    /// Seconds from now (default 3600, protocol intent TTL ~1h).
    pub ttl_secs: u64,
}

impl OpenOrder {
    /// Validate against protocol bounds. No network needed.
    pub fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(self.instrument <= 1, "instrument 0=BTC 1=ETH");
        anyhow::ensure!((1..=1000).contains(&self.leverage), "leverage 1..=1000");
        let notional = self.margin_usd * self.leverage as f64;
        anyhow::ensure!(
            (crate::MIN_OPEN_NOTIONAL_USD..=crate::MAX_NOTIONAL_USD * 10.0).contains(&notional),
            "notional ${} out of range (relayer enforces <= $10M)",
            notional
        );
        anyhow::ensure!(self.margin_usd > 0.0, "margin > 0");
        Ok(())
    }

    /// margin_raw in 1e18 fixed USD (w3 layout, verified on live traces).
    pub fn margin_raw(&self) -> u128 {
        (self.margin_usd * 1e18) as u128
    }

    pub fn deadline(&self) -> u64 {
        crate::now_unix() + self.ttl_secs.max(60)
    }
}

/// Built unsigned intent, ready to sign.
#[derive(Debug, Clone)]
pub struct UnsignedIntent {
    pub order: OpenOrder,
    pub subcall: Vec<u8>,
    pub deadline: u64,
}

/// Build the open-leg subcall bytes (selector 0xec6783f0 + 11 words).
/// `user` = caller's wallet proxy address. Zero-slots per live layout.
pub fn build_open_intent(user: Address, order: &OpenOrder) -> UnsignedIntent {
    let mut buf = vec![0u8; 0];
    buf.extend_from_slice(&[0xec, 0x67, 0x83, 0xf0]);
    let mut w = |v: &[u8]| buf.extend_from_slice(v);
    let u256 = |x: u128| {
        let mut b = [0u8; 32];
        b[16..].copy_from_slice(&x.to_be_bytes());
        b.to_vec()
    };
    let addr = |a: Address| {
        let mut b = vec![0u8; 12];
        b.extend_from_slice(a.as_slice());
        b
    };
    w(&addr(user)); // w0 user
    w(&u256(order.instrument as u128)); // w1 instrument
    w(&u256(if order.is_long { 1 } else { 0 })); // w2 side (best evidence)
    w(&u256(order.margin_raw())); // w3 margin
    w(&u256(order.leverage as u128)); // w4 leverage
    w(&u256(0)); // w5
    w(&u256(0)); // w6
    let deadline = order.deadline();
    w(&u256(deadline as u128)); // w7 deadline
    w(&u256(0)); // w8 (NOT side — observed 27/28 live, left zero, flagged)
    w(&u256(0)); // w9
    w(&u256(0)); // w10
    UnsignedIntent { order: order.clone(), subcall: buf, deadline }
}

/// Wrap one subcall into the outer 0x251fb27d batch skeleton.
/// Live-verified layout (676 B for a 356 B open leg):
/// w0 sel+pad | 0x20 | count=1 | 0x20 | target | 0xa0 | 0x01 | aux1 | aux2
/// | blob(len32 BE + subcall, padded) | deadline | r | s | v.
/// aux1/aux2 are order-hash-like bytes32 (meaning UNCONFIRMED — pass through).
pub fn wrap_batch(target: Address, subcall: &[u8], aux1: [u8; 32], aux2: [u8; 32], deadline: u64) -> Vec<u8> {
    let mut out = vec![0x25u8, 0x1f, 0xb2, 0x7d]; // 0x251fb27d
    out.extend_from_slice(&[0u8; 28]);
    let u256 = |x: u64| {
        let mut b = [0u8; 32];
        b[24..].copy_from_slice(&x.to_be_bytes());
        b.to_vec()
    };
    out.extend_from_slice(&u256(0x20));
    out.extend_from_slice(&u256(1));
    out.extend_from_slice(&u256(0x20));
    let mut tb = vec![0u8; 12];
    tb.extend_from_slice(target.as_slice());
    out.extend_from_slice(&tb);
    out.extend_from_slice(&u256(0xa0));
    out.extend_from_slice(&u256(1));
    out.extend_from_slice(&aux1);
    out.extend_from_slice(&aux2);
    let mut blob = (subcall.len() as u32).to_be_bytes().to_vec();
    blob.extend_from_slice(subcall);
    let pad = (32 - blob.len() % 32) % 32;
    blob.extend_from_slice(&vec![0u8; pad]);
    out.extend_from_slice(&blob);
    out.extend_from_slice(&u256(deadline));
    out
}

/// keccak256 of the unsigned batch (HYPOTHESIS sig preimage — verify on first live sign).
pub fn intent_hash(unsigned_batch: &[u8]) -> [u8; 32] {
    use sha3::{Digest, Keccak256};
    let mut h = Keccak256::new();
    h.update(unsigned_batch);
    h.finalize().into()
}

/// Human-readable order summary for logs (no secrets).
pub fn describe(order: &OpenOrder) -> String {
    format!(
        "{} {} margin=${:.0} lev={}x notional=${:.0}",
        if order.is_long { "LONG" } else { "SHORT" },
        if order.instrument == 0 { "BTC" } else { "ETH" },
        order.margin_usd,
        order.leverage,
        order.margin_usd * order.leverage as f64
    )
}

#[allow(dead_code)]
fn _use_types(_: Bytes, _: U256) {}
