![raper-sdk](assets/logo.svg)

# raper-sdk — direct-work SDK for Papertrade on HyperEVM 999

Read-only-first SDK (alloy-based) for the Papertrade perps protocol.
Default RPC `https://rpc.hyperliquid.xyz/evm` (WSS sibling), chain id asserted
to 999. No keys required for any view call.

> Protocol contracts are **unverified** (bytecode + `eth_call` probes +
> Heimdall decompile only). Exchange logic (`0x0f3f…49ee`, 168 selectors) can
> be replaced on upgrade — re-verify the codehash via `eth_getCode` before
> relying on views or encoders.

## Modules

| Module | File | What it does |
|---|---|---|
| `addresses` | `src/addresses.rs` | Canonical addresses, meta-tx/open selectors, protocol bounds and fee constants |
| `provider` | `src/provider.rs` | Alloy HTTP/WS provider constructors, default URLs, `assert_chain` (999) |
| `bindings` | `src/bindings.rs` | `alloy::sol!` contract bindings with verified selectors only (`Exchange`, `Wallet`, `Paper`) |
| `views` | `src/views.rs` | Read-only protocol views over `eth_call` (`collateralScale`, `instrumentCount`, `nextPositionId`, `totalQueued`, `totalLockedMargin`, `liquidationFeeRate`, `tradingPaused`) + `impl_code` codehash check |
| `tx` | `src/tx.rs` | **Encoding-only** builders for phase 2 (`encode_open` for `0xec6783f0`); nothing signs or sends; unknown slots zero-filled, must be re-verified |
| `rpc` | `src/rpc.rs` | Minimal JSON-RPC client (`eth_blockNumber`, `eth_getBlockByNumber`, `eth_call`, `eth_getCode`), `selector()` (keccak, first 4 bytes), `u256_f64()` |
| `decoder` (separate crate) | `crates/decoder/` | Intent decoder for `0x251fb27d` meta-txs; see `crates/decoder/README.md` |

`Exchange` binding exposes `collateralScale`, `instrumentCount`,
`nextPositionId`, `totalQueued`, `totalLockedMargin`, `liquidationFeeRate`,
`tradingPaused`, `treasury`, `balances(address)`, `positions(uint256)`,
`owner`, `oracle`, `liquidate`, `close`, `harvest`. `Wallet` exposes `owner`,
`exchange`, `sessionKeyManager`. `Paper` exposes `name`, `symbol`,
`decimals`, `totalSupply`, `balanceOf`, `owner`.

## Example: read views + decode an intent (pseudocode, no keys)

```rust
// Pseudocode — compiles against this workspace's API shape, values illustrative.
use raper_sdk::{rpc::Rpc, views::Views, provider};
use decoder::{words_of, scan_anchors, parse_open};

async fn example(rpc_url: &str, calldata_hex: &str) -> anyhow::Result<()> {
    // 1. Read-only views, no keys.
    let rpc = Rpc::new(rpc_url)?;
    let views = Views::new(rpc.clone());
    let paused: bool = views.trading_paused().await?;
    let fee_rate: f64 = views.liquidation_fee_rate().await?; // / 1e18
    let queued_usd: f64 = views.total_queued().await?;       // / 1e12 / 1e6
    println!("paused={paused} fee={fee_rate} queued=${queued_usd:.2}");

    // 2. Guard against silent upgrades.
    let code: String = views.impl_code(raper_sdk::EXCHANGE_IMPL).await?;
    assert!(!code.is_empty(), "impl code erased — stop");

    // 3. Decode an observed 0x251fb27d intent (no signing, no sending).
    let words = words_of(calldata_hex);
    let scan = scan_anchors(&words);
    if scan.has_core_leg {
        if let Some(open) = parse_open(calldata_hex) {
            // open.user / .instrument / .margin_raw / .leverage / .deadline / .is_long
            println!("open: inst={} lev={} long={}", open.instrument, open.leverage, open.is_long);
        }
    }
    Ok(())
}
```

`tx::encode_open(user, instrument, margin_raw, leverage, deadline, is_long)`
builds the `0xec6783f0` subcall for phase 2. It only encodes; signing and
submission are out of scope, and reserved slots are zero-filled placeholders.

## Unit scales

| Quantity | Raw encoding | Conversion to human units |
|---|---|---|
| Margin (`margin_raw`) | `uint256` open-leg word 3 (low 128 bits used) | USD = `margin_raw / 1e12 (COLLATERAL_SCALE) / 1e6` (USDC) |
| `totalQueued` / `totalLockedMargin` | `uint256` views | USD, same `/ 1e12 / 1e6` divisor as margin |
| Leverage | `uint32` open-leg word 4 | Plain multiplier, max `1000` (`MAX_LEVERAGE`) |
| Instrument id | `uint32` open-leg word 1 | `0` = BTC (pos. mult. 814.598), `1` = ETH (pos. mult. 483.979) |
| Deadline | `uint64` open-leg word 7 | Unix timestamp (seconds) |
| Side | open-leg word 8 | `is_long = word != 0` |
| `liquidationFeeRate` | `uint256` view | Fraction = raw `/ 1e18` |
| `u256_f64` helper | hex word | `f64` assuming `1e18` scale (saturates above `u128::MAX`) |
| Bust buffer | constant `0.0005` | ~5 bps toward entry |
| Haircut | constants | Deadband `1/50000` (0.2 bps), base `0.10` (10 %), win fee `0.02` (2 %) |
| Notional bounds | constants | Min open `$10_000`, max `$10_000_000` |

Execution price = BBO mid of the execution block (no sandwich, no stale-mid
lock). Position multipliers above are protocol constants from `addresses`.
