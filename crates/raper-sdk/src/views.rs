//! Read-only protocol views (verified live via eth_call).

use super::rpc::{selector, Rpc};
use crate::COLLATERAL_SCALE;

async fn u256(rpc: &Rpc, to: &str, sig: &str) -> anyhow::Result<u128> {
    let v = rpc.eth_call(to, &format!("0x{}", selector(sig))).await?;
    Ok(u128::from_str_radix(v.trim_start_matches("0x"), 16).unwrap_or(0))
}

/// Collateral USD: raw / 1e12 (collateralScale) / 1e6 (USDC).
pub fn collateral_usd(raw: u128) -> f64 {
    raw as f64 / COLLATERAL_SCALE / 1e6
}

pub async fn collateral_scale(rpc: &Rpc) -> anyhow::Result<f64> {
    Ok(u256(rpc, super::EXCHANGE, "collateralScale()").await? as f64)
}

pub async fn instrument_count(rpc: &Rpc) -> anyhow::Result<u64> {
    Ok(u256(rpc, super::EXCHANGE, "instrumentCount()").await? as u64)
}

pub async fn next_position_id(rpc: &Rpc) -> anyhow::Result<u64> {
    Ok(u256(rpc, super::EXCHANGE, "nextPositionId()").await? as u64)
}

pub async fn total_queued_usd(rpc: &Rpc) -> anyhow::Result<f64> {
    Ok(collateral_usd(u256(rpc, super::EXCHANGE, "totalQueued()").await?))
}

pub async fn total_locked_margin_usd(rpc: &Rpc) -> anyhow::Result<f64> {
    Ok(collateral_usd(u256(rpc, super::EXCHANGE, "totalLockedMargin()").await?))
}

pub async fn liquidation_fee_rate(rpc: &Rpc) -> anyhow::Result<f64> {
    Ok(u256(rpc, super::EXCHANGE, "liquidationFeeRate()").await? as f64 / 1e18)
}

pub async fn trading_paused(rpc: &Rpc) -> anyhow::Result<bool> {
    Ok(u256(rpc, super::EXCHANGE, "tradingPaused()").await? != 0)
}
