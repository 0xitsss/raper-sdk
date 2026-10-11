//! Shared state-API client (papertrade exchange, read-only).

use serde::Deserialize;

#[derive(Debug, Deserialize, Clone)]
#[allow(dead_code)]
pub struct TradeEvent {
    pub seq: String,
    pub ts: i64,
    pub wallet: String,
    pub instrument: String,
    pub side: String,
    pub leverage: i64,
    #[serde(rename = "notionalUsd")]
    pub notional: f64,
    pub kind: String,
    pub entry: Option<f64>,
    pub exit: Option<f64>,
    #[serde(rename = "pnlUsd")]
    pub pnl: Option<f64>,
}

#[derive(Debug, Deserialize)]
struct TapeResp {
    events: Vec<TradeEvent>,
}

pub async fn fetch_recent(base: &str) -> anyhow::Result<Vec<TradeEvent>> {
    let client = reqwest::Client::builder()
        .user_agent("raper-sdk/0.1")
        .timeout(std::time::Duration::from_secs(15))
        .build()?;
    let url = format!("{}/query/protocol/trades/recent", base.trim_end_matches('/'));
    let resp: TapeResp = client
        .get(&url)
        .header("Accept", "application/json")
        .header("Referer", "https://exchange.papertrade.xyz/trade/btc")
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    Ok(resp.events)
}
