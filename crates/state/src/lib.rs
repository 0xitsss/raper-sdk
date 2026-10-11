//! Read-only REST client for the public Papertrade state API.
//!
//! Base URL: `https://exchange.papertrade.xyz`, no auth. The API expects the
//! same `Referer` as the web frontend (`/trade/btc` page).
//!
//! Endpoints covered:
//! - `GET /query/protocol/summary` — balances / activity / fees / paper / source.
//! - `GET /state/house/delta?coin=BTC|ETH` — house net-delta snapshot.
//! - `GET /query/protocol/trades/recent` — public trade tape.
//! - `GET /query/protocol/paper/activity` — PAPER token events.
//! - `GET /state/leaderboard/accounts?page=&pageSize=[&sortKey=&sortDir=]`
//!
//! All money amounts are bigint strings scaled by 1e18 USD, but the server
//! sometimes emits them (and counters) as JSON numbers — every scalar field
//! is therefore `Option<...>` with a string-or-number tolerant deserializer
//! from [`tolerant`], and every list defaults to empty (missing *or* null).
//!
//! ```ignore
//! let api = StateClient::new("https://exchange.papertrade.xyz")?;
//! let summary = api.summary().await?;
//! let btc = api.delta("BTC").await?;
//! let top = api.leaderboard(0, 50).await?;
//! # Ok::<(), anyhow::Error>(())
//! ```

use std::collections::HashMap;
use std::time::Duration;

use anyhow::Context;
use serde::Deserialize;
use serde_json::Value;

/// Referer required by the public API (same value the web frontend sends).
pub const REFERER: &str = "https://exchange.papertrade.xyz/trade/btc";
/// User-Agent sent with every request.
pub const USER_AGENT: &str = "paper-raper-state/0.1";

/// Typed client over the public state API.
#[derive(Debug, Clone)]
pub struct StateClient {
    base: String,
    client: reqwest::Client,
}

impl StateClient {
    /// Build a client for `base` (e.g. `https://exchange.papertrade.xyz`).
    /// A trailing slash is stripped; no I/O happens here.
    pub fn new(base: impl Into<String>) -> anyhow::Result<Self> {
        let base = base.into().trim_end_matches('/').to_string();
        anyhow::ensure!(!base.is_empty(), "empty base URL");
        let client = reqwest::Client::builder()
            .user_agent(USER_AGENT)
            .timeout(Duration::from_secs(15))
            .build()
            .context("building HTTP client")?;
        Ok(Self { base, client })
    }

    /// Base URL as given (without trailing slash).
    pub fn base(&self) -> &str {
        &self.base
    }

    /// Join `path` (with or without leading `/`) onto the base URL.
    fn endpoint(&self, path: &str) -> String {
        if path.starts_with('/') {
            format!("{}{}", self.base, path)
        } else {
            format!("{}/{}", self.base, path)
        }
    }

    /// Raw GET with the standard headers. No status check — the caller
    /// decides (leaderboard needs to see a 400 to fall back).
    async fn get_raw(&self, path: &str) -> anyhow::Result<reqwest::Response> {
        let url = self.endpoint(path);
        self.client
            .get(&url)
            .header("Accept", "application/json")
            .header("Referer", REFERER)
            .send()
            .await
            .with_context(|| format!("GET {url}"))
    }

    /// GET `path` and decode the JSON body as `T`.
    pub async fn get_json<T>(&self, path: &str) -> anyhow::Result<T>
    where
        T: serde::de::DeserializeOwned,
    {
        decode_json(self.get_raw(path).await?).await
    }

    /// `GET /query/protocol/summary`.
    pub async fn summary(&self) -> anyhow::Result<SummaryResponse> {
        self.get_json("/query/protocol/summary").await
    }

    /// Path for `GET /state/house/delta?coin=...`. The coin is uppercased
    /// (`btc` -> `BTC`); anything else passes through for forward compat.
    pub fn delta_path(coin: &str) -> String {
        format!("/state/house/delta?coin={}", coin.trim().to_uppercase())
    }

    /// `GET /state/house/delta?coin=BTC|ETH`.
    pub async fn delta(&self, coin: &str) -> anyhow::Result<DeltaResponse> {
        self.get_json(&Self::delta_path(coin)).await
    }

    /// `GET /query/protocol/trades/recent`.
    pub async fn recent_trades(&self) -> anyhow::Result<RecentTradesResponse> {
        self.get_json("/query/protocol/trades/recent").await
    }

    /// `GET /query/protocol/paper/activity`.
    pub async fn paper_activity(&self) -> anyhow::Result<PaperActivityResponse> {
        self.get_json("/query/protocol/paper/activity").await
    }

    /// `(primary, fallback)` paths for the leaderboard. Primary carries the
    /// default sort (`sortKey=realizedPnl&sortDir=desc`); fallback is the
    /// minimal `page`/`pageSize` form used when the server answers 400.
    pub fn leaderboard_paths(page: u32, size: u32) -> (String, String) {
        (
            format!(
                "/state/leaderboard/accounts?page={page}&pageSize={size}&sortKey=realizedPnl&sortDir=desc"
            ),
            format!("/state/leaderboard/accounts?page={page}&pageSize={size}"),
        )
    }

    /// `GET /state/leaderboard/accounts`. Tries the sorted form first; on
    /// HTTP 400 retries with bare `page`/`pageSize`.
    pub async fn leaderboard(&self, page: u32, size: u32) -> anyhow::Result<LeaderboardResponse> {
        let (primary, fallback) = Self::leaderboard_paths(page, size);
        let resp = self.get_raw(&primary).await?;
        if resp.status() == reqwest::StatusCode::BAD_REQUEST {
            return self.get_json(&fallback).await;
        }
        decode_json(resp).await
    }
}

async fn decode_json<T>(resp: reqwest::Response) -> anyhow::Result<T>
where
    T: serde::de::DeserializeOwned,
{
    let url = resp.url().to_string();
    let status = resp.status();
    resp.error_for_status()
        .with_context(|| format!("GET {url} -> HTTP {status}"))?
        .json::<T>()
        .await
        .with_context(|| format!("decoding JSON from {url}"))
}

/// String-or-number tolerant deserializers. Every helper maps JSON `null`
/// (and a missing field via `#[serde(default)]`) to `None`/empty, accepts
/// both string and numeric encodings, and never fails on scalar drift;
/// genuinely unparseable scalars degrade to `None`/skipped instead of
/// erroring.
pub mod tolerant {
    use serde::{Deserialize, Deserializer};
    use serde_json::Value;

    /// `Option<String>` from a string, number, or bool (`42` -> `"42"`).
    pub fn opt_string<'de, D>(d: D) -> Result<Option<String>, D::Error>
    where
        D: Deserializer<'de>,
    {
        Ok(match Value::deserialize(d)? {
            Value::Null => None,
            Value::String(s) => Some(s),
            Value::Number(n) => Some(n.to_string()),
            Value::Bool(b) => Some(b.to_string()),
            _ => None,
        })
    }

    /// `Option<i64>` from a number or a numeric string (`"10"` -> `10`,
    /// `"1e3"` -> `1000`, `true` -> `1`).
    pub fn opt_i64<'de, D>(d: D) -> Result<Option<i64>, D::Error>
    where
        D: Deserializer<'de>,
    {
        Ok(match Value::deserialize(d)? {
            Value::Null => None,
            Value::Number(n) => n
                .as_i64()
                .or_else(|| n.as_u64().and_then(|v| i64::try_from(v).ok()))
                .or_else(|| n.as_f64().map(|f| f as i64)),
            Value::String(s) => {
                let s = s.trim();
                if s.is_empty() {
                    None
                } else if let Ok(v) = s.parse::<i64>() {
                    Some(v)
                } else if let Ok(v) = s.parse::<u64>() {
                    i64::try_from(v).ok()
                } else {
                    s.parse::<f64>().ok().map(|f| f as i64)
                }
            }
            Value::Bool(b) => Some(i64::from(b)),
            _ => None,
        })
    }

    /// `Option<u64>`; negatives and garbage degrade to `None`.
    pub fn opt_u64<'de, D>(d: D) -> Result<Option<u64>, D::Error>
    where
        D: Deserializer<'de>,
    {
        fn from_f64(f: f64) -> Option<u64> {
            if f.is_finite() && f >= 0.0 {
                Some(f as u64)
            } else {
                None
            }
        }
        Ok(match Value::deserialize(d)? {
            Value::Null => None,
            Value::Number(n) => n
                .as_u64()
                .or_else(|| n.as_i64().and_then(|v| u64::try_from(v).ok()))
                .or_else(|| n.as_f64().and_then(from_f64)),
            Value::String(s) => {
                let s = s.trim();
                if s.is_empty() {
                    None
                } else if let Ok(v) = s.parse::<u64>() {
                    Some(v)
                } else if let Ok(v) = s.parse::<i64>() {
                    u64::try_from(v).ok()
                } else {
                    s.parse::<f64>().ok().and_then(from_f64)
                }
            }
            Value::Bool(b) => Some(u64::from(b)),
            _ => None,
        })
    }

    /// `Option<f64>` from a number, numeric string, or bool.
    pub fn opt_f64<'de, D>(d: D) -> Result<Option<f64>, D::Error>
    where
        D: Deserializer<'de>,
    {
        Ok(match Value::deserialize(d)? {
            Value::Null => None,
            Value::Number(n) => n.as_f64(),
            Value::String(s) => {
                let s = s.trim();
                if s.is_empty() {
                    None
                } else {
                    s.parse::<f64>().ok()
                }
            }
            Value::Bool(b) => Some(if b { 1.0 } else { 0.0 }),
            _ => None,
        })
    }

    /// `Option<bool>` from a bool, `0`/`1`, or `"true"`/`"false"`/`"1"`/`"0"`.
    pub fn opt_bool<'de, D>(d: D) -> Result<Option<bool>, D::Error>
    where
        D: Deserializer<'de>,
    {
        Ok(match Value::deserialize(d)? {
            Value::Null => None,
            Value::Bool(b) => Some(b),
            Value::Number(n) => n
                .as_i64()
                .map(|v| v != 0)
                .or_else(|| n.as_u64().map(|v| v != 0))
                .or_else(|| n.as_f64().map(|f| f != 0.0)),
            Value::String(s) => match s.trim().to_ascii_lowercase().as_str() {
                "true" | "1" => Some(true),
                "false" | "0" => Some(false),
                _ => None,
            },
            _ => None,
        })
    }

    /// `Vec<String>` for scalar arrays like delta `values`: each element may
    /// be a string, number, or bool; `null`/missing -> empty, null elements
    /// and objects are skipped, a lone scalar wraps into one element.
    pub fn string_vec<'de, D>(d: D) -> Result<Vec<String>, D::Error>
    where
        D: Deserializer<'de>,
    {
        fn scalar(v: Value) -> Option<String> {
            match v {
                Value::String(s) => Some(s),
                Value::Number(n) => Some(n.to_string()),
                Value::Bool(b) => Some(b.to_string()),
                _ => None,
            }
        }
        Ok(match Value::deserialize(d)? {
            Value::Null => Vec::new(),
            Value::Array(items) => items.into_iter().filter_map(scalar).collect(),
            single => scalar(single).into_iter().collect(),
        })
    }

    /// `Vec<T>` that also accepts JSON `null` as empty (missing is handled
    /// by `#[serde(default)]`).
    pub fn struct_vec<'de, D, T>(d: D) -> Result<Vec<T>, D::Error>
    where
        D: Deserializer<'de>,
        T: Deserialize<'de>,
    {
        Ok(Option::<Vec<T>>::deserialize(d)?.unwrap_or_default())
    }
}

// ---------------------------------------------------------------------------
// Responses
// ---------------------------------------------------------------------------

/// `GET /query/protocol/summary`.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SummaryResponse {
    #[serde(default)]
    pub balances: Option<Balances>,
    #[serde(default)]
    pub activity: Option<SummaryActivity>,
    #[serde(default)]
    pub fees: Option<SummaryFees>,
    #[serde(default)]
    pub paper: Option<PaperInfo>,
    #[serde(default)]
    pub source: Option<SourceInfo>,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Balances {
    #[serde(default, deserialize_with = "tolerant::opt_string")]
    pub lp: Option<String>,
    #[serde(default, deserialize_with = "tolerant::opt_string")]
    pub queue: Option<String>,
    #[serde(default, deserialize_with = "tolerant::opt_string")]
    pub tvl: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SummaryActivity {
    #[serde(default, deserialize_with = "tolerant::opt_string")]
    pub volume: Option<String>,
    #[serde(default, deserialize_with = "tolerant::opt_string")]
    pub open: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SummaryFees {
    #[serde(default, deserialize_with = "tolerant::opt_string")]
    pub pending: Option<String>,
    #[serde(default, deserialize_with = "tolerant::opt_string")]
    pub lifetime: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaperInfo {
    #[serde(default, deserialize_with = "tolerant::opt_string")]
    pub supply: Option<String>,
    #[serde(default, deserialize_with = "tolerant::opt_string")]
    pub staked: Option<String>,
    #[serde(default, deserialize_with = "tolerant::opt_string")]
    pub tracked_lp: Option<String>,
    #[serde(default, deserialize_with = "tolerant::opt_string")]
    pub accumulator: Option<String>,
    #[serde(default, deserialize_with = "tolerant::opt_string")]
    pub rate: Option<String>,
    #[serde(default, deserialize_with = "tolerant::opt_string")]
    pub cliff: Option<String>,
    #[serde(default, deserialize_with = "tolerant::opt_string")]
    pub cap: Option<String>,
    #[serde(default, deserialize_with = "tolerant::opt_string")]
    pub excess: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SourceInfo {
    #[serde(default, deserialize_with = "tolerant::opt_i64")]
    pub block: Option<i64>,
    #[serde(default, deserialize_with = "tolerant::opt_string")]
    pub at: Option<String>,
}

/// `GET /state/house/delta?coin=BTC|ETH`.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeltaResponse {
    #[serde(default)]
    pub delta: Option<DeltaInfo>,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeltaInfo {
    #[serde(default, deserialize_with = "tolerant::opt_string")]
    pub coin: Option<String>,
    #[serde(default, deserialize_with = "tolerant::opt_string")]
    pub mark: Option<String>,
    #[serde(default, deserialize_with = "tolerant::opt_i64")]
    pub mark_ts: Option<i64>,
    #[serde(default, deserialize_with = "tolerant::opt_i64")]
    pub position_count: Option<i64>,
    #[serde(default, deserialize_with = "tolerant::opt_string")]
    pub range: Option<String>,
    #[serde(default, deserialize_with = "tolerant::opt_i64")]
    pub samples: Option<i64>,
    #[serde(default, deserialize_with = "tolerant::string_vec")]
    pub values: Vec<String>,
}

/// `GET /query/protocol/trades/recent`.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RecentTradesResponse {
    #[serde(default, deserialize_with = "tolerant::opt_bool")]
    pub ok: Option<bool>,
    #[serde(default, deserialize_with = "tolerant::opt_i64")]
    pub count: Option<i64>,
    #[serde(default, deserialize_with = "tolerant::struct_vec")]
    pub events: Vec<TradeEvent>,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TradeEvent {
    #[serde(default, deserialize_with = "tolerant::opt_string")]
    pub seq: Option<String>,
    #[serde(default, deserialize_with = "tolerant::opt_i64")]
    pub ts: Option<i64>,
    #[serde(default, deserialize_with = "tolerant::opt_string")]
    pub wallet: Option<String>,
    #[serde(default, deserialize_with = "tolerant::opt_string")]
    pub instrument: Option<String>,
    #[serde(default, deserialize_with = "tolerant::opt_i64")]
    pub instrument_id: Option<i64>,
    #[serde(default, deserialize_with = "tolerant::opt_string")]
    pub side: Option<String>,
    #[serde(default, deserialize_with = "tolerant::opt_i64")]
    pub leverage: Option<i64>,
    #[serde(default, deserialize_with = "tolerant::opt_string")]
    pub notional_usd: Option<String>,
    #[serde(default, deserialize_with = "tolerant::opt_string")]
    pub intent_id: Option<String>,
    #[serde(default, deserialize_with = "tolerant::opt_string")]
    pub position_id: Option<String>,
    #[serde(default, deserialize_with = "tolerant::opt_string")]
    pub kind: Option<String>,
    #[serde(default, deserialize_with = "tolerant::opt_string")]
    pub entry: Option<String>,
    #[serde(default, deserialize_with = "tolerant::opt_string")]
    pub exit: Option<String>,
    #[serde(default, deserialize_with = "tolerant::opt_string")]
    pub pnl_usd: Option<String>,
}

/// `GET /query/protocol/paper/activity`.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaperActivityResponse {
    #[serde(default, deserialize_with = "tolerant::struct_vec")]
    pub items: Vec<PaperEvent>,
    #[serde(default, deserialize_with = "tolerant::opt_bool")]
    pub ok: Option<bool>,
    #[serde(default, deserialize_with = "tolerant::opt_i64")]
    pub count: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaperEvent {
    #[serde(default, deserialize_with = "tolerant::opt_i64")]
    pub block_number: Option<i64>,
    #[serde(default, deserialize_with = "tolerant::opt_i64")]
    pub log_index: Option<i64>,
    #[serde(default, deserialize_with = "tolerant::opt_i64")]
    pub timestamp_ms: Option<i64>,
    #[serde(default, deserialize_with = "tolerant::opt_string")]
    pub tx_hash: Option<String>,
    #[serde(default, deserialize_with = "tolerant::opt_string")]
    pub amount_raw: Option<String>,
    #[serde(default, deserialize_with = "tolerant::opt_string")]
    pub kind: Option<String>,
    #[serde(default, deserialize_with = "tolerant::opt_string")]
    pub user_address: Option<String>,
}

/// `GET /state/leaderboard/accounts`.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LeaderboardResponse {
    #[serde(default, deserialize_with = "tolerant::opt_bool")]
    pub ok: Option<bool>,
    #[serde(default, deserialize_with = "tolerant::opt_i64")]
    pub count: Option<i64>,
    #[serde(default)]
    pub summary: Option<LeaderboardSummary>,
    #[serde(default, deserialize_with = "tolerant::struct_vec")]
    pub accounts: Vec<LeaderboardAccount>,
}

/// Unspecified `summary` object: any keys are preserved in `extra`.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct LeaderboardSummary {
    #[serde(flatten)]
    pub extra: HashMap<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LeaderboardAccount {
    #[serde(default, deserialize_with = "tolerant::opt_string")]
    pub address: Option<String>,
    #[serde(default, deserialize_with = "tolerant::opt_string")]
    pub realized_pnl: Option<String>,
    #[serde(default, deserialize_with = "tolerant::opt_string")]
    pub total_volume: Option<String>,
    /// Any further per-account keys (forward compat with `...`).
    #[serde(flatten)]
    pub extra: HashMap<String, Value>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn from<T: serde::de::DeserializeOwned>(json: &str) -> T {
        serde_json::from_str(json).expect("synthetic JSON must parse")
    }

    #[test]
    fn client_trims_base_and_joins_paths() {
        let c = StateClient::new("https://exchange.papertrade.xyz/").unwrap();
        assert_eq!(c.base(), "https://exchange.papertrade.xyz");
        assert_eq!(
            c.endpoint("/query/protocol/summary"),
            "https://exchange.papertrade.xyz/query/protocol/summary"
        );
        assert_eq!(
            c.endpoint("query/protocol/summary"),
            "https://exchange.papertrade.xyz/query/protocol/summary"
        );
    }

    #[test]
    fn client_rejects_empty_base() {
        assert!(StateClient::new("").is_err());
        assert!(StateClient::new("///").is_err());
    }

    #[test]
    fn delta_path_uppercases_coin() {
        assert_eq!(StateClient::delta_path("btc"), "/state/house/delta?coin=BTC");
        assert_eq!(StateClient::delta_path("ETH"), "/state/house/delta?coin=ETH");
    }

    #[test]
    fn leaderboard_paths_have_sorted_primary_and_bare_fallback() {
        let (primary, fallback) = StateClient::leaderboard_paths(0, 50);
        assert_eq!(
            primary,
            "/state/leaderboard/accounts?page=0&pageSize=50&sortKey=realizedPnl&sortDir=desc"
        );
        assert_eq!(fallback, "/state/leaderboard/accounts?page=0&pageSize=50");
    }

    #[test]
    fn summary_mixed_string_and_number_amounts() {
        let r: SummaryResponse = from(
            r#"{
                "balances": {"lp": "123000000000000000000000", "queue": 5000, "tvl": null},
                "activity": {"volume": "999000000000000000000", "open": "10"},
                "fees": {"pending": "0", "lifetime": 42},
                "paper": {"supply": "1000000000000000000000000", "staked": "1",
                          "trackedLp": 2, "accumulator": "3", "rate": "4",
                          "cliff": null, "cap": "6", "excess": "7"},
                "source": {"block": 12345678, "at": "2026-01-01T00:00:00Z"}
            }"#,
        );
        let b = r.balances.unwrap();
        assert_eq!(b.lp.as_deref(), Some("123000000000000000000000"));
        assert_eq!(b.queue.as_deref(), Some("5000"));
        assert_eq!(b.tvl, None);
        assert_eq!(r.fees.unwrap().lifetime.as_deref(), Some("42"));
        let p = r.paper.unwrap();
        assert_eq!(p.tracked_lp.as_deref(), Some("2"));
        assert_eq!(p.cliff, None);
        let s = r.source.unwrap();
        assert_eq!(s.block, Some(12345678));
        assert_eq!(s.at.as_deref(), Some("2026-01-01T00:00:00Z"));
    }

    #[test]
    fn summary_empty_object_gives_nones() {
        let r: SummaryResponse = from("{}");
        assert_eq!(r.balances, None);
        assert_eq!(r.source, None);
    }

    #[test]
    fn delta_values_accept_mixed_scalars_and_missing() {
        let r: DeltaResponse = from(
            r#"{"delta": {"coin": "BTC", "mark": "97500.5", "markTs": 1700000000000,
                           "positionCount": "3", "range": "24h", "samples": 288,
                           "values": ["100", "200", 300, 4.5, null]}}"#,
        );
        let d = r.delta.unwrap();
        assert_eq!(d.coin.as_deref(), Some("BTC"));
        assert_eq!(d.mark.as_deref(), Some("97500.5"));
        assert_eq!(d.mark_ts, Some(1700000000000));
        assert_eq!(d.position_count, Some(3));
        assert_eq!(
            d.values,
            vec!["100".to_string(), "200".to_string(), "300".to_string(), "4.5".to_string()]
        );
    }

    #[test]
    fn delta_null_and_missing_is_tolerant() {
        let r: DeltaResponse = from(r#"{"delta": null}"#);
        assert_eq!(r.delta, None);
        let r: DeltaResponse = from("{}");
        assert_eq!(r.delta, None);
        let r: DeltaResponse = from(r#"{"delta": {"coin": "ETH"}}"#);
        let d = r.delta.unwrap();
        assert_eq!(d.values, Vec::<String>::new());
        assert_eq!(d.samples, None);
    }

    #[test]
    fn recent_trades_envelope_and_event_tolerance() {
        let r: RecentTradesResponse = from(
            r#"{"ok": true, "count": "2", "events": [
                {"seq": 7, "ts": "1700000000000", "wallet": "0xabc", "instrument": "BTC",
                 "instrumentId": "0", "side": "long", "leverage": "10",
                 "notionalUsd": "10000000000000000000000", "intentId": 1, "positionId": "5",
                 "kind": "open", "entry": "97000", "exit": null, "pnlUsd": null},
                {"seq": "8", "ts": 1700000001000, "wallet": "0xdef", "instrument": "ETH",
                 "instrumentId": 1, "side": "short", "leverage": 5,
                 "notionalUsd": 5000, "kind": "close", "exit": "2500", "pnlUsd": "-12.5"}
            ]}"#,
        );
        assert_eq!(r.ok, Some(true));
        assert_eq!(r.count, Some(2));
        assert_eq!(r.events.len(), 2);
        assert_eq!(r.events[0].seq.as_deref(), Some("7"));
        assert_eq!(r.events[0].ts, Some(1700000000000));
        assert_eq!(r.events[0].leverage, Some(10));
        assert_eq!(r.events[0].intent_id.as_deref(), Some("1"));
        assert_eq!(r.events[0].exit, None);
        assert_eq!(r.events[1].pnl_usd.as_deref(), Some("-12.5"));
        assert_eq!(r.events[1].notional_usd.as_deref(), Some("5000"));
    }

    #[test]
    fn recent_trades_missing_and_null_events_give_empty() {
        let r: RecentTradesResponse = from("{}");
        assert_eq!(r.ok, None);
        assert!(r.events.is_empty());
        let r: RecentTradesResponse = from(r#"{"ok": 1, "events": null}"#);
        assert_eq!(r.ok, Some(true));
        assert!(r.events.is_empty());
    }

    #[test]
    fn paper_activity_items_and_empty_forms() {
        let r: PaperActivityResponse = from(
            r#"{"items": [{"blockNumber": 100, "logIndex": "3", "timestampMs": 1700000000000,
                           "txHash": "0xhash", "amountRaw": "5000000000000000000",
                           "kind": "stake", "userAddress": "0xuser"}]}"#,
        );
        assert_eq!(r.items.len(), 1);
        let e = &r.items[0];
        assert_eq!(e.block_number, Some(100));
        assert_eq!(e.log_index, Some(3));
        assert_eq!(e.amount_raw.as_deref(), Some("5000000000000000000"));

        let r: PaperActivityResponse = from("{}");
        assert!(r.items.is_empty());
        let r: PaperActivityResponse = from(r#"{"items": null}"#);
        assert!(r.items.is_empty());
    }

    #[test]
    fn leaderboard_accounts_and_summary_extras() {
        let r: LeaderboardResponse = from(
            r#"{"ok": 1, "count": 2, "summary": {"totalAccounts": 2, "updatedAt": "x"},
                "accounts": [
                    {"address": "0xa", "realizedPnl": "123", "totalVolume": 456, "rank": 1},
                    {"address": "0xb", "realizedPnl": null, "totalVolume": "0"}
                ]}"#,
        );
        assert_eq!(r.ok, Some(true));
        assert_eq!(r.count, Some(2));
        let s = r.summary.unwrap();
        assert_eq!(s.extra.get("totalAccounts"), Some(&Value::from(2)));
        assert_eq!(r.accounts.len(), 2);
        assert_eq!(r.accounts[0].total_volume.as_deref(), Some("456"));
        assert_eq!(r.accounts[0].extra.get("rank"), Some(&Value::from(1)));
        assert_eq!(r.accounts[1].realized_pnl, None);
    }

    #[test]
    fn leaderboard_minimal_form() {
        let r: LeaderboardResponse = from("{}");
        assert_eq!(r.ok, None);
        assert_eq!(r.summary, None);
        assert!(r.accounts.is_empty());
    }

    #[test]
    fn tolerant_helpers_cover_scalar_drift() {
        #[derive(Debug, PartialEq, Deserialize)]
        struct Probe {
            #[serde(default, deserialize_with = "tolerant::opt_bool")]
            b: Option<bool>,
            #[serde(default, deserialize_with = "tolerant::opt_f64")]
            f: Option<f64>,
            #[serde(default, deserialize_with = "tolerant::opt_u64")]
            u: Option<u64>,
            #[serde(default, deserialize_with = "tolerant::opt_i64")]
            i: Option<i64>,
            #[serde(default, deserialize_with = "tolerant::opt_string")]
            s: Option<String>,
        }
        let p: Probe = from(r#"{"b": "false", "f": "1.5", "u": "6", "i": "1e3", "s": true}"#);
        assert_eq!(p.b, Some(false));
        assert_eq!(p.f, Some(1.5));
        assert_eq!(p.u, Some(6));
        assert_eq!(p.i, Some(1000));
        assert_eq!(p.s.as_deref(), Some("true"));

        let p: Probe = from(r#"{"b": 0, "f": null, "u": -1, "i": "", "s": null}"#);
        assert_eq!(p.b, Some(false));
        assert_eq!(p.f, None);
        assert_eq!(p.u, None);
        assert_eq!(p.i, None);
        assert_eq!(p.s, None);
    }
}
