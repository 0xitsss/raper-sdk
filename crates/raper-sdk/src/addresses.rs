//! Verified on-chain addresses (HyperEVM 999).

/// Exchange proxy (user-facing entry point).
pub const EXCHANGE: &str = "0x6cd5661646289fb6e65ea5c032310fded797d0a2";
/// Exchange logic (re-verify codehash on upgrade).
pub const EXCHANGE_IMPL: &str = "0x0f3febfc94876b0c895f7acecdc8f5c863b549ee";
/// User-wallet logic (shared by all 925-byte wallet proxies).
pub const WALLET_IMPL: &str = "0xe0bc9cc7b067060aafccbaa3e250700c9cdd7262";
/// PAPER token proxy.
pub const PAPER: &str = "0xe40f17915daa230324030003a197cdaef2261c0e";
/// Protocol owner EOA (upgrades, fee rates, guardians — NOT a multisig).
pub const OWNER: &str = "0xb915fa41e824d6aa31bb833ee81220c0f2c8ea0f";
/// PriceOracle (delegatecall target from open path).
pub const PRICE_ORACLE: &str = "0xcd617f984158a4f5d287ddee0e8eb0fed204916d";

/// Meta-tx entry on wallet logic.
pub const SEL_META_TX: &str = "251fb27d";
/// Open leg: (user, instrument, ?, margin, leverage, ?, ?, deadline, ?, ?, ?).
pub const SEL_OPEN: &str = "ec6783f0";
/// Close-variant legs.
pub const SEL_CLOSE_A: &str = "2792e706";
pub const SEL_CLOSE_B: &str = "8d09f23f";

/// Protocol bounds (state/trading + docs).
pub const MAX_LEVERAGE: u32 = 1000;
pub const MAX_NOTIONAL_USD: f64 = 10_000_000.0;
pub const MIN_OPEN_NOTIONAL_USD: f64 = 10_000.0;
/// 1e12 (collateralScale).
pub const COLLATERAL_SCALE: f64 = 1e12;
/// Bust buffer ~5bps toward entry.
pub const BUST_BUFFER: f64 = 0.0005;
/// Deadband 0.2bps, base haircut 10%, win fee 2%.
pub const DEADBAND: f64 = 1.0 / 50000.0;
pub const HAIRCUT_BASE: f64 = 0.10;
pub const WIN_FEE: f64 = 0.02;
pub const RATE_MULT: f64 = 15000.0;
pub const REF_NOTIONAL: f64 = 100_000.0;

/// Position multiplier per instrument id (0=BTC, 1=ETH).
pub fn pos_mult(instrument: u32) -> f64 {
    match instrument {
        1 => 483.979,
        _ => 814.598,
    }
}
