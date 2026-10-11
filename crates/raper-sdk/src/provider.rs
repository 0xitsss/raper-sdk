//! Alloy provider for HyperEVM 999.

use alloy::providers::{Provider, ProviderBuilder};
use alloy::transports::http::reqwest::Url;

/// HTTP provider (blocks, calls, receipts).
pub async fn http_provider(url: &str) -> anyhow::Result<impl Provider + Clone> {
    let url: Url = url.parse()?;
    Ok(ProviderBuilder::new().connect_http(url))
}

/// WS provider (subscriptions: new blocks, pending txs).
pub async fn ws_provider(url: &str) -> anyhow::Result<impl Provider + Clone> {
    Ok(ProviderBuilder::new().connect(url).await?)
}

pub const HTTP_URL: &str = "https://rpc.hyperliquid.xyz/evm";
pub const WS_URL: &str = "wss://rpc.hyperliquid.xyz/evm";

/// Chain id assertion for HyperEVM mainnet.
pub async fn assert_chain<P: Provider>(p: &P) -> anyhow::Result<()> {
    let id = p.get_chain_id().await?;
    anyhow::ensure!(id == 999, "expected HyperEVM 999, got {}", id);
    Ok(())
}
