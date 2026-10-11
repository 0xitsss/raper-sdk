//! raper-sdk — direct-work SDK for Papertrade on HyperEVM 999.
//!
//! Verified on-chain (eth_call + Heimdall decompile):
//! - Exchange proxy 0x6cd5...797d0a2 -> logic 0x0f3f...49ee
//! - User-wallet proxy template (925 B) -> logic 0xe0bc...7262
//!   (permissioned meta-tx executor, entry 0x251fb27d)
//! - PAPER 0xe40f...144eeee
//! - Owner EOA 0xb915fa... (all proxies + PAPER)
//!
//! Phase 1: read-only (no keys). Phase 2 needs own wallet via app deposit.

pub mod addresses;
pub mod bindings;
pub mod metrics;
pub mod provider;
pub mod rpc;
pub mod tx;
pub mod views;

pub use addresses::*;
