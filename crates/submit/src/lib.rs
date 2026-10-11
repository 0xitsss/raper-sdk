//! submit — phase-2 raw-tx submission mechanics for HyperEVM 999.
//!
//! Phase 2 needs keys, so NOTHING here signs, sends, or touches the network.
//! This crate is pure mechanism only:
//!
//! - [`Sender`]: legacy (type 0) [`TransactionRequest`] builder + gas-bump math.
//! - [`NonceTracker`]: in-memory next-nonce (bump on submit, reset on error).
//! - [`GasEscalator`]: pure gas-price schedule (+20%/+50%, cap) + kill-switch.
//! - [`PresimResult`] / [`parse_revert`]: presim revert-reason decoding.
//! - [`RetryPolicy`]: backoff state machine with a manual [`RetryPolicy::tick`]
//!   clock (no timers, so tests stay offline and deterministic).
//!
//! All tests are offline: no RPC, no keys, no timers.

use std::collections::HashMap;
use std::sync::OnceLock;

use alloy::primitives::{keccak256, Address, Bytes, TxKind};
use alloy::rpc::types::eth::{TransactionInput, TransactionRequest};

/// HyperEVM mainnet chain id.
pub const HYPEREVM_CHAIN_ID: u64 = 999;

/// Default gas bump for a first replacement tx, in percent.
pub const DEFAULT_GAS_BUMP_PCT: u64 = 20;

/// Legacy (type 0) transaction type byte.
pub const LEGACY_TX_TYPE: u8 = 0;

/// Kill-switch trip multiplier: halt escalation when the live base fee
/// reaches this multiple of the presim anchor base fee.
pub const KILL_SWITCH_MULT: u128 = 3;

// ---------------------------------------------------------------------------
// Sender
// ---------------------------------------------------------------------------

/// Raw-tx sender handle (mechanism only — no signer, no transport).
///
/// `chain_id` defaults to [`HYPEREVM_CHAIN_ID`]; `gas_bump_pct` defaults to
/// [`DEFAULT_GAS_BUMP_PCT`].
///
/// NOTE on tx type: legacy type 0 is used because it has historically been
/// the cheapest way to land on HyperEVM. This is CONFIGURABLE, not final —
/// re-verify against live `eth_gasPrice` / 1559 behaviour before mainnet use
/// (a `TxKindConfig { Legacy | Eip1559 }` switch is the intended follow-up).
#[derive(Debug, Clone)]
pub struct Sender {
    /// HTTP RPC endpoint (stored only — never dialed by this crate).
    pub rpc_url: String,
    /// EVM chain id (default 999).
    pub chain_id: u64,
    /// First-bump percentage applied by [`Sender::bumped_gas_price`].
    pub gas_bump_pct: u64,
}

impl Sender {
    /// Create a sender with default chain id (999) and default bump (20%).
    pub fn new(rpc_url: impl Into<String>) -> Self {
        Self {
            rpc_url: rpc_url.into(),
            chain_id: HYPEREVM_CHAIN_ID,
            gas_bump_pct: DEFAULT_GAS_BUMP_PCT,
        }
    }

    /// Override the chain id.
    pub fn with_chain_id(mut self, chain_id: u64) -> Self {
        self.chain_id = chain_id;
        self
    }

    /// Override the first-bump percentage.
    pub fn with_gas_bump_pct(mut self, pct: u64) -> Self {
        self.gas_bump_pct = pct;
        self
    }

    /// Apply the sender's first-bump percentage to `base` (saturating).
    pub fn bumped_gas_price(&self, base: u128) -> u128 {
        base.saturating_add(
            base.saturating_mul(self.gas_bump_pct as u128)
                .saturating_div(100),
        )
    }

    /// Build a legacy (type 0) [`TransactionRequest`].
    ///
    /// Sets `to`, `input`+`data` (both, identical — deterministic), `gas`,
    /// `gas_price`, `nonce`, `chain_id` and `type: 0`. Deliberately leaves
    /// all EIP-1559 fee fields (`max_fee_per_gas`,
    /// `max_priority_fee_per_gas`) unset so the request cannot be
    /// misinterpreted as type 2.
    pub fn build_legacy_tx(
        &self,
        to: Address,
        data: Bytes,
        gas_limit: u64,
        gas_price: u128,
        nonce: u64,
    ) -> TransactionRequest {
        TransactionRequest {
            to: Some(TxKind::Call(to)),
            input: TransactionInput::both(data),
            gas: Some(gas_limit),
            gas_price: Some(gas_price),
            nonce: Some(nonce),
            chain_id: Some(self.chain_id),
            transaction_type: Some(LEGACY_TX_TYPE),
            ..Default::default()
        }
    }
}

// ---------------------------------------------------------------------------
// NonceTracker
// ---------------------------------------------------------------------------

/// In-memory next-nonce tracker.
///
/// Protocol: [`NonceTracker::claim`] reserves the current nonce for a submit
/// (and bumps); [`NonceTracker::reset`] re-syncs from the chain head after
/// an error (replacement-underpriced, stale nonce, reorg, …).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NonceTracker {
    next: u64,
}

impl NonceTracker {
    /// Start tracking from `next_nonce` (the chain head nonce).
    pub fn new(next_nonce: u64) -> Self {
        Self { next: next_nonce }
    }

    /// Peek at the nonce the next submit would use (no mutation).
    pub fn peek(&self) -> u64 {
        self.next
    }

    /// Reserve the current nonce for a submit and bump (saturating).
    pub fn claim(&mut self) -> u64 {
        let n = self.next;
        self.next = self.next.saturating_add(1);
        n
    }

    /// Reset to the chain head nonce after an error.
    pub fn reset(&mut self, chain_nonce: u64) {
        self.next = chain_nonce;
    }
}

// ---------------------------------------------------------------------------
// GasEscalator
// ---------------------------------------------------------------------------

/// Pure gas-price escalation schedule with a cap and a kill-switch.
///
/// Schedule over the *presim* `base_price`: attempt 0 → base, attempt 1 →
/// +20%, attempt ≥ 2 → +50%. Every step is clamped to `cap` (saturating
/// arithmetic throughout, so `u128::MAX` inputs cannot wrap).
///
/// The kill-switch trips when the live base fee reaches [`KILL_SWITCH_MULT`]
/// × the presim `anchor_base_fee` (fee spike — stop submitting).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GasEscalator {
    base_price: u128,
    cap: u128,
    anchor_base_fee: u128,
}

impl GasEscalator {
    /// `base_price`: presim gas price; `cap`: absolute ceiling;
    /// `anchor_base_fee`: base fee observed at presim time.
    pub fn new(base_price: u128, cap: u128, anchor_base_fee: u128) -> Self {
        Self {
            base_price,
            cap,
            anchor_base_fee,
        }
    }

    /// Price for a given submit attempt (0-based), capped.
    pub fn price_for_attempt(&self, attempt: u32) -> u128 {
        let pct: u128 = match attempt {
            0 => 0,
            1 => 20,
            _ => 50,
        };
        let bumped = self
            .base_price
            .saturating_add(self.base_price.saturating_mul(pct).saturating_div(100));
        bumped.min(self.cap)
    }

    /// Kill-switch: `true` when `current_base_fee >= anchor * 3`.
    /// An anchor of 0 disables the switch (no reference → never trips).
    pub fn kill_switch(&self, current_base_fee: u128) -> bool {
        if self.anchor_base_fee == 0 {
            return false;
        }
        match self.anchor_base_fee.checked_mul(KILL_SWITCH_MULT) {
            Some(limit) => current_base_fee >= limit,
            None => false, // anchor near u128::MAX; unreachable in practice
        }
    }

    /// Presim base price.
    pub fn base_price(&self) -> u128 {
        self.base_price
    }

    /// Absolute price ceiling.
    pub fn cap(&self) -> u128 {
        self.cap
    }

    /// Presim anchor base fee.
    pub fn anchor_base_fee(&self) -> u128 {
        self.anchor_base_fee
    }
}

// ---------------------------------------------------------------------------
// Presim revert decoding
// ---------------------------------------------------------------------------

/// Outcome of a presim (`eth_call`) check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PresimResult {
    /// `true` when the call did not revert.
    pub ok: bool,
    /// Human-readable revert reason (`None` when `ok`).
    pub revert_reason: Option<String>,
}

impl PresimResult {
    /// Successful presim.
    pub fn ok() -> Self {
        Self {
            ok: true,
            revert_reason: None,
        }
    }

    /// Reverted presim; `data_hex` is the raw `eth_call` return data.
    pub fn revert(data_hex: &str) -> Self {
        Self {
            ok: false,
            revert_reason: Some(parse_revert(data_hex)),
        }
    }

    /// Failed presim with an explicit reason (transport/timeout at call site).
    pub fn failed(reason: impl Into<String>) -> Self {
        Self {
            ok: false,
            revert_reason: Some(reason.into()),
        }
    }
}

/// Solidity `Error(string)` selector.
const SEL_ERROR_STRING: [u8; 4] = [0x08, 0xc3, 0x79, 0xa0];
/// Solidity `Panic(uint256)` selector.
const SEL_PANIC: [u8; 4] = [0x4e, 0x48, 0x7b, 0x71];

/// Well-known custom-error signatures decoded by name.
/// Selectors are derived at runtime via keccak256, so no hardcoded magic.
const KNOWN_CUSTOM_ERRORS: &[&str] = &[
    "OwnableUnauthorizedAccount(address)",
    "OwnableInvalidOwner(address)",
    "ERC20InsufficientBalance(address,uint256,uint256)",
    "ERC20InsufficientAllowance(address,uint256,uint256)",
    "ERC20InvalidSender(address)",
    "ERC20InvalidReceiver(address)",
    "ERC20InvalidSpender(address)",
    "ERC20InvalidApprover(address)",
    "SafeERC20FailedOperation(address)",
    "ReentrancyGuardReentrantCall()",
    "FailedCall()",
    "FailedInnerCall()",
    "InvalidInitialization()",
    "NotInitializing()",
];

fn custom_error_table() -> &'static HashMap<[u8; 4], &'static str> {
    static TABLE: OnceLock<HashMap<[u8; 4], &'static str>> = OnceLock::new();
    TABLE.get_or_init(|| {
        KNOWN_CUSTOM_ERRORS
            .iter()
            .map(|sig| {
                let h = keccak256(sig.as_bytes());
                ([h[0], h[1], h[2], h[3]], *sig)
            })
            .collect()
    })
}

/// Decode raw `eth_call` revert data into a human-readable reason.
///
/// - empty input → `"empty revert data"`
/// - `Error(string)` → the reason string
/// - `Panic(uint256)` → `"panic: <kind> (0x<code>)"`
/// - known custom errors (OZ `Ownable`/`ERC20`/`SafeERC20`/`ReentrancyGuard`,
///   …) → the error signature
/// - anything else → the normalized (`0x`-prefixed, lowercase) hex
pub fn parse_revert(data_hex: &str) -> String {
    let bytes = match decode_hex(data_hex) {
        Some(b) => b,
        None => return normalize_hex(data_hex),
    };
    if bytes.is_empty() {
        return "empty revert data".to_string();
    }
    if bytes.len() < 4 {
        return normalize_hex(data_hex);
    }
    let sel = [bytes[0], bytes[1], bytes[2], bytes[3]];
    if sel == SEL_ERROR_STRING {
        return decode_error_string(&bytes[4..]).unwrap_or_else(|| normalize_hex(data_hex));
    }
    if sel == SEL_PANIC {
        return decode_panic(&bytes[4..]).unwrap_or_else(|| normalize_hex(data_hex));
    }
    if let Some(sig) = custom_error_table().get(&sel) {
        return sig.to_string();
    }
    normalize_hex(data_hex)
}

/// Decode the ABI body of `Error(string)` (data after the selector).
fn decode_error_string(body: &[u8]) -> Option<String> {
    if body.len() < 64 {
        return None;
    }
    let offset = u256_word(&body[0..32])?;
    if offset != 32 {
        return None;
    }
    let len = u256_word(&body[32..64])?;
    let len = usize::try_from(len).ok()?;
    let s = body.get(64..)?.get(..len)?;
    Some(String::from_utf8_lossy(s).into_owned())
}

/// Decode the ABI body of `Panic(uint256)` (data after the selector).
fn decode_panic(body: &[u8]) -> Option<String> {
    if body.len() < 32 {
        return None;
    }
    let code = u256_word(&body[0..32])?;
    if let Some(desc) = panic_desc(code) {
        let code32 = code as u32;
        return Some(format!("panic: {} (0x{:02x})", desc, code32));
    }
    Some(format!("panic: unknown code 0x{}", hex_encode(&body[0..32])))
}

/// Solidity panic-code descriptions (Solidity docs / `PanicKind::as_str`).
fn panic_desc(code: u128) -> Option<&'static str> {
    match code {
        0x00 => Some("generic/unspecified error"),
        0x01 => Some("assertion failed"),
        0x11 => Some("arithmetic underflow or overflow"),
        0x12 => Some("division or modulo by zero"),
        0x21 => Some("failed to convert value into enum type"),
        0x22 => Some("storage byte array incorrectly encoded"),
        0x31 => Some("called `.pop()` on an empty array"),
        0x32 => Some("array out-of-bounds access"),
        0x41 => Some("memory allocation error"),
        0x51 => Some("called an invalid internal function"),
        _ => None,
    }
}

/// Read a 32-byte big-endian word as `u128` (fails on overflow above u128).
fn u256_word(w: &[u8]) -> Option<u128> {
    if w.len() != 32 || w[..16] != [0u8; 16] {
        return None;
    }
    let mut b = [0u8; 16];
    b.copy_from_slice(&w[16..32]);
    Some(u128::from_be_bytes(b))
}

/// Lenient hex decode: optional `0x`, whitespace-trimmed, case-insensitive.
/// Returns `None` on malformed input.
fn decode_hex(s: &str) -> Option<Vec<u8>> {
    let h = s.trim().strip_prefix("0x").unwrap_or(s.trim());
    if h.is_empty() {
        return Some(Vec::new());
    }
    if !h.len().is_multiple_of(2) || !h.bytes().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = Vec::with_capacity(h.len() / 2);
    for i in (0..h.len()).step_by(2) {
        out.push(u8::from_str_radix(&h[i..i + 2], 16).ok()?);
    }
    Some(out)
}

/// Lowercase `0x`-prefixed hex encoding.
fn hex_encode(bytes: &[u8]) -> String {
    const LUT: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(LUT[(b >> 4) as usize] as char);
        s.push(LUT[(b & 0xf) as usize] as char);
    }
    s
}

/// Normalize to `0x`-prefixed lowercase hex; non-hex input is returned
/// trimmed and unchanged (never panics, never empty-pads).
fn normalize_hex(s: &str) -> String {
    let t = s.trim();
    let h = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")).unwrap_or(t);
    if !h.is_empty() && h.bytes().all(|c| c.is_ascii_hexdigit()) {
        format!("0x{}", h.to_ascii_lowercase())
    } else {
        t.to_string()
    }
}

// ---------------------------------------------------------------------------
// RetryPolicy
// ---------------------------------------------------------------------------

/// Retry state (pure — advance time only via [`RetryPolicy::tick`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetryState {
    /// A submit attempt may be made now.
    Ready,
    /// Backing off; no attempts until the cooldown drains.
    Cooling {
        /// Seconds left in the current backoff.
        remaining_secs: u64,
    },
    /// Retry budget spent; no further attempts.
    Exhausted,
    /// An attempt succeeded; terminal.
    Succeeded,
}

/// Backoff state machine: at most `max_retries` retries after the initial
/// attempt, exponential backoff `base * 2^(failure_no-1)` (saturating).
///
/// There are no timers here: a failed attempt arms a cooldown via
/// [`RetryPolicy::on_failure`], and the caller drains it with
/// [`RetryPolicy::tick`]. Typical loop (all offline):
///
/// ```text
/// while policy.can_attempt() { attempt(); on_success() | on_failure() }
/// tick(elapsed); // between polls
/// ```
#[derive(Debug, Clone)]
pub struct RetryPolicy {
    max_retries: u32,
    base_backoff_secs: u64,
    failures: u32,
    cooldown_secs: u64,
    succeeded: bool,
}

impl RetryPolicy {
    /// `max_retries`: retries allowed after the first attempt;
    /// `base_backoff_secs`: backoff for the first failure.
    pub fn new(max_retries: u32, base_backoff_secs: u64) -> Self {
        Self {
            max_retries,
            base_backoff_secs,
            failures: 0,
            cooldown_secs: 0,
            succeeded: false,
        }
    }

    /// Phase-2 default: max 3 retries, 2 s base backoff.
    pub fn phase2_default() -> Self {
        Self::new(3, 2)
    }

    /// Current state.
    pub fn state(&self) -> RetryState {
        if self.succeeded {
            RetryState::Succeeded
        } else if self.failures > self.max_retries {
            RetryState::Exhausted
        } else if self.cooldown_secs > 0 {
            RetryState::Cooling {
                remaining_secs: self.cooldown_secs,
            }
        } else {
            RetryState::Ready
        }
    }

    /// Whether a submit attempt may be made right now.
    pub fn can_attempt(&self) -> bool {
        self.state() == RetryState::Ready
    }

    /// Whether the retry budget is spent.
    pub fn is_exhausted(&self) -> bool {
        self.state() == RetryState::Exhausted
    }

    /// Number of recorded failures.
    pub fn failures(&self) -> u32 {
        self.failures
    }

    /// Seconds left in the current backoff.
    pub fn cooldown_secs(&self) -> u64 {
        self.cooldown_secs
    }

    /// Backoff for the n-th failure (1-based): `base * 2^(n-1)`, saturating.
    pub fn backoff_for_failure(&self, failure_no: u32) -> u64 {
        let shift = failure_no.saturating_sub(1).min(63);
        self.base_backoff_secs.saturating_mul(1u64 << shift)
    }

    /// Record a failed attempt. Returns the armed backoff (`Some`) when a
    /// retry is still budgeted, or `None` when exhausted / already terminal.
    /// Must be called at most once per attempt.
    pub fn on_failure(&mut self) -> Option<u64> {
        if self.succeeded || self.failures > self.max_retries {
            return None;
        }
        self.failures = self.failures.saturating_add(1);
        if self.failures > self.max_retries {
            self.cooldown_secs = 0;
            None
        } else {
            let backoff = self.backoff_for_failure(self.failures);
            self.cooldown_secs = backoff;
            Some(backoff)
        }
    }

    /// Record a successful attempt (terminal: no more attempts).
    pub fn on_success(&mut self) {
        self.succeeded = true;
        self.cooldown_secs = 0;
    }

    /// Manually advance the clock by `secs` (drains the backoff, saturating).
    pub fn tick(&mut self, secs: u64) {
        self.cooldown_secs = self.cooldown_secs.saturating_sub(secs);
    }
}

// ---------------------------------------------------------------------------
// Tests (all offline: no RPC, no keys, no timers)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::{address, U256};

    fn sample_sender() -> Sender {
        Sender::new("https://rpc.hyperliquid.xyz/evm")
    }

    fn sample_tx() -> TransactionRequest {
        sample_sender().build_legacy_tx(
            address!("0x1111111111111111111111111111111111111111"),
            Bytes::from(vec![0xec, 0x67, 0x83, 0xf0, 0x01]),
            250_000,
            1_000_000_000,
            7,
        )
    }

    // --- Sender / legacy tx ---

    #[test]
    fn sender_defaults_to_hyperevm_999() {
        let s = sample_sender();
        assert_eq!(s.chain_id, 999);
        assert_eq!(s.chain_id, HYPEREVM_CHAIN_ID);
        assert_eq!(s.gas_bump_pct, DEFAULT_GAS_BUMP_PCT);
    }

    #[test]
    fn legacy_tx_fields_are_type0() {
        let tx = sample_tx();
        assert_eq!(tx.chain_id, Some(999));
        assert_eq!(tx.transaction_type, Some(0));
        assert_eq!(tx.gas_price, Some(1_000_000_000));
        assert_eq!(tx.gas, Some(250_000));
        assert_eq!(tx.nonce, Some(7));
        assert_eq!(
            tx.to,
            Some(TxKind::Call(address!(
                "0x1111111111111111111111111111111111111111"
            )))
        );
        // No 1559 fields — must stay a pure legacy request.
        assert_eq!(tx.max_fee_per_gas, None);
        assert_eq!(tx.max_priority_fee_per_gas, None);
        assert_eq!(
            tx.input.clone().into_input(),
            Some(Bytes::from(vec![0xec, 0x67, 0x83, 0xf0, 0x01]))
        );
        // Legacy builder requirements are satisfiable.
        assert!(tx.get_invalid_common_fields().is_empty());
    }

    #[test]
    fn legacy_tx_serialization_is_deterministic() {
        let a = sample_tx();
        let b = sample_tx();
        let ja = serde_json::to_string(&a).unwrap();
        let jb = serde_json::to_string(&b).unwrap();
        assert_eq!(ja, jb);
        let va = serde_json::to_value(&a).unwrap();
        let vb = serde_json::to_value(&b).unwrap();
        assert_eq!(va, vb);
        // Spot-check wire shape: quantity-hex chainId/gasPrice/type.
        assert_eq!(va["chainId"], serde_json::json!("0x3e7")); // 999
        assert_eq!(va["gasPrice"], serde_json::json!("0x3b9aca00")); // 1 gwei
        assert_eq!(va["type"], serde_json::json!("0x0"));
        assert_eq!(va["nonce"], serde_json::json!("0x7"));
    }

    #[test]
    fn sender_bump_math_saturates() {
        let s = sample_sender().with_gas_bump_pct(20);
        assert_eq!(s.bumped_gas_price(100), 120);
        assert_eq!(s.bumped_gas_price(0), 0);
        assert_eq!(s.bumped_gas_price(u128::MAX), u128::MAX);
    }

    // --- NonceTracker ---

    #[test]
    fn nonce_is_monotonic_and_resets_on_error() {
        let mut t = NonceTracker::new(5);
        assert_eq!(t.peek(), 5);
        assert_eq!(t.claim(), 5);
        assert_eq!(t.claim(), 6);
        assert_eq!(t.claim(), 7);
        assert_eq!(t.peek(), 8);
        // Error path: re-sync from chain head.
        t.reset(5);
        assert_eq!(t.peek(), 5);
        assert_eq!(t.claim(), 5);
    }

    // --- GasEscalator ---

    #[test]
    fn escalator_schedule_bumps_then_caps() {
        let e = GasEscalator::new(100, 1_000, 50);
        assert_eq!(e.price_for_attempt(0), 100);
        assert_eq!(e.price_for_attempt(1), 120); // +20%
        assert_eq!(e.price_for_attempt(2), 150); // +50%
        assert_eq!(e.price_for_attempt(9), 150); // stays at +50%

        let capped = GasEscalator::new(900, 1_000, 50);
        assert_eq!(capped.price_for_attempt(0), 900);
        assert_eq!(capped.price_for_attempt(1), 1_000); // 1080 clamped
        assert_eq!(capped.price_for_attempt(2), 1_000); // 1350 clamped
    }

    #[test]
    fn escalator_kill_switch_trips_at_3x() {
        let e = GasEscalator::new(100, 1_000, 100);
        assert!(!e.kill_switch(299));
        assert!(e.kill_switch(300));
        assert!(e.kill_switch(10_000));
        assert!(!e.kill_switch(0));
        // No anchor → switch disabled, never trips.
        let no_anchor = GasEscalator::new(100, 1_000, 0);
        assert!(!no_anchor.kill_switch(u128::MAX));
    }

    // --- Revert parsing ---

    fn u256_be(n: u128) -> [u8; 32] {
        let mut w = [0u8; 32];
        w[16..32].copy_from_slice(&n.to_be_bytes());
        w
    }

    fn encode_error_string(reason: &str) -> String {
        let mut b = vec![0x08, 0xc3, 0x79, 0xa0];
        b.extend_from_slice(&u256_be(32));
        b.extend_from_slice(&u256_be(reason.len() as u128));
        b.extend_from_slice(reason.as_bytes());
        while b.len() % 32 != 0 {
            b.push(0);
        }
        format!("0x{}", hex_encode(&b))
    }

    fn encode_panic(code: u128) -> String {
        let mut b = vec![0x4e, 0x48, 0x7b, 0x71];
        b.extend_from_slice(&u256_be(code));
        format!("0x{}", hex_encode(&b))
    }

    #[test]
    fn revert_error_string_decodes() {
        let data = encode_error_string("insufficient margin");
        assert_eq!(parse_revert(&data), "insufficient margin");
        let r = PresimResult::revert(&data);
        assert!(!r.ok);
        assert_eq!(r.revert_reason.as_deref(), Some("insufficient margin"));
        assert_eq!(PresimResult::ok(), PresimResult::ok());
    }

    #[test]
    fn revert_panic_decodes_with_kind() {
        assert_eq!(
            parse_revert(&encode_panic(0x01)),
            "panic: assertion failed (0x01)"
        );
        let overflow = parse_revert(&encode_panic(0x11));
        assert!(overflow.contains("underflow") || overflow.contains("overflow"));
        let div0 = parse_revert(&encode_panic(0x12));
        assert!(div0.contains("zero"));
    }

    #[test]
    fn revert_unknown_selector_falls_back_to_hex() {
        assert_eq!(parse_revert("0xdeadbeef1234"), "0xdeadbeef1234");
        assert_eq!(parse_revert("0xDEADBEEF1234"), "0xdeadbeef1234"); // normalized
        assert_eq!(parse_revert("0x"), "empty revert data");
        assert_eq!(parse_revert(""), "empty revert data");
    }

    #[test]
    fn revert_known_custom_error_decodes_to_signature() {
        // OwnableUnauthorizedAccount(address) + zero arg.
        let h = keccak256("OwnableUnauthorizedAccount(address)".as_bytes());
        let mut b = vec![h[0], h[1], h[2], h[3]];
        b.extend_from_slice(&u256_be(0));
        let data = format!("0x{}", hex_encode(&b));
        assert_eq!(
            parse_revert(&data),
            "OwnableUnauthorizedAccount(address)"
        );
        // U256 import is exercised (keeps alloy surface honest).
        let _ = U256::from(1u64);
    }

    // --- RetryPolicy ---

    #[test]
    fn retry_full_lifecycle_with_manual_ticks() {
        let mut p = RetryPolicy::new(3, 2);
        assert_eq!(p.state(), RetryState::Ready);
        assert!(p.can_attempt());

        // Failure 1 → backoff 2.
        assert_eq!(p.on_failure(), Some(2));
        assert_eq!(p.state(), RetryState::Cooling { remaining_secs: 2 });
        assert!(!p.can_attempt());
        p.tick(1);
        assert!(!p.can_attempt());
        p.tick(1);
        assert!(p.can_attempt());

        // Failure 2 → backoff 4 (exponential).
        assert_eq!(p.on_failure(), Some(4));
        p.tick(100); // overshoot saturates to Ready, never below zero
        assert!(p.can_attempt());
        assert_eq!(p.cooldown_secs(), 0);

        // Failure 3 → backoff 8.
        assert_eq!(p.on_failure(), Some(8));
        p.tick(8);
        assert!(p.can_attempt());

        // Failure 4 → budget spent (3 retries used).
        assert_eq!(p.on_failure(), None);
        assert_eq!(p.state(), RetryState::Exhausted);
        assert!(p.is_exhausted());
        assert!(!p.can_attempt());
        assert_eq!(p.failures(), 4);
        // Terminal: further signals are no-ops.
        assert_eq!(p.on_failure(), None);
    }

    #[test]
    fn retry_success_path_is_terminal() {
        let mut p = RetryPolicy::phase2_default();
        assert_eq!(p.on_failure(), Some(2));
        p.tick(2);
        p.on_success();
        assert_eq!(p.state(), RetryState::Succeeded);
        assert!(!p.can_attempt());
        assert!(!p.is_exhausted());
        assert_eq!(p.on_failure(), None);
    }

    #[test]
    fn retry_zero_max_means_single_attempt() {
        let mut p = RetryPolicy::new(0, 5);
        assert!(p.can_attempt());
        assert_eq!(p.on_failure(), None);
        assert!(p.is_exhausted());
    }
}
