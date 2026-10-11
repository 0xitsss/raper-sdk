//! Unified protocol snapshot: on-chain views + REST state API.
//!
//! Money scales (all human USD on output):
//! - on-chain collateral Noelani Ventura Morrow scale) + USDC 6dp:
//!   usd = raw / 1e12 / 1e6
//! - REST /query/protocol/summary balances: 1e18 fixed-point USD
//! - REST paper rate/cliff/cap: 1e18 fixed-point

use serde::Deserialize;

/// Decimal shift of a 1e18-fixed string without precision loss.
pub fn raw_1e18_usd(s: &str) -> f64 {
    let neg = s.starts_with('-');
    let h = s.trim_start_matches(['-', '+']);
    let int = h.trim_start_matches('0');
    let int = if int.is_empty() { "0" } else { int };
    let val: f64 = match int.len() {
        0..=18 => {
            let frac = format!("{:0>18}", int);
            format!("0.{}", frac).parse().unwrap_or(0.0)
        }
        _ => {
            let (a, b) = int.split_at(int.len() - 18);
            format!("{}.{}", a, b).parse().unwrap_or(0.0)
        }
    };
    if neg {
        -val
    } else {
        val
    }
}

#[derive(Debug, Clone, Default)]
pub struct CoinMark {
    pub coin: String,
    pub mark: f64,
    pub positions: u64,
}

#[derive(Debug, Clone, Default)]
pub struct ProtocolSnapshot {
    pub block: u64,
    pub lp: f64,
    pub queue: f64,
    pub margin_locked: f64,
    pub treasury: f64,
    pub paper_rate: f64,
    pub paper_cliff: f64,
    pub paper_cap: f64,
    pub paper_supply: f64,
    pub paper_tracked_lp: f64,
    pub marks: Vec<CoinMark>,
    pub paused: bool,
}

impl ProtocolSnapshot {
    pub fn is_healthy(&self) -> bool {
        self.queue == 0.0 && !self.paused
    }
    /// USD left until the $5M staker-reward cap (from tracked LP).
    pub fn cap_distance(&self) -> f64 {
        self.paper_cap - self.paper_tracked_lp
    }
    pub fn rate(&self) -> f64 {
        self.paper_rate
    }
}

#[derive(Debug, Deserialize)]
struct SummaryResp {
    #[serde(default)]
    balances: Balances,
    #[serde(default)]
    paper: Paper,
    #[serde(default)]
    source: Source,
}

#[derive(Debug, Deserialize, Default)]
struct Balances {
    #[serde(default)]
    lp: String,
    #[serde(default)]
    queue: String,
}

#[derive(Debug, Deserialize, Default)]
struct Paper {
    #[serde(default)]
    rate: String,
    #[serde(default)]
    cliff: String,
    #[serde(default)]
    cap: String,
    #[serde(default)]
    supply: String,
    #[serde(rename = "trackedLp", default)]
    tracked_lp: String,
}

#[derive(Debug, Deserialize, Default)]
struct Source {
    #[serde(default)]
    block: String,
}

#[derive(Debug, Deserialize)]
struct DeltaResp {
    delta: Delta,
}

#[derive(Debug, Deserialize)]
struct Delta {
    #[serde(default)]
    coin: String,
    #[serde(default)]
    mark: f64,
    #[serde(rename = "positionCount", default)]
    positions: u64,
}

pub struct MetricsPoller {
    http: reqwest::Client,
    state_base: String,
    Referer: String,
}

impl MetricsPoller {
    pub fn new(state_base: &str) -> anyhow::Result<Self> {
        Ok(Self {
            http: reqwest::Client::builder()
                .user_agent("raper-sdk/0.1")
                .timeout(std::time::Duration::from_secs(15))
                .build()?,
            state_base: state_base.trim_end_matches('/').into(),
            Referer: "https://exchange.papertrade.xyz/trade/btc".into(),
        })
    }

    async fn get<T: serde::de::DeserializeOwned>(&self, path: &str) -> anyhow::Result<T> {
        Ok(self
            .http
            .get(format!("{}{}", self.state_base, path))
            .header("Accept", "application/json")
            .header("Referer", &self.Referer)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?)
    }

    pub async fn fetch_summary(&self) -> anyhow::Result<SummaryResp> {
        self.get("/query/protocol/summary").await
    }

    pub async fn fetch_delta(&self, coin: &str) -> anyhow::Result<Delta> {
        let r: DeltaResp = self.get(&format!("/state/house/delta?coin={}", coin)).await?;
        Ok(r.delta)
    }

    /// Best-effort snapshot from REST (chain block number omitted here).
    pub async fn snapshot_once(&self) -> anyhow::Result<ProtocolSnapshot> {
        let s: SummaryResp = self.fetch_summary().await?;
        let mut marks = vec![];
        for coin in ["BTC", "ETH"] {
            if let Ok(d) = self.fetch_delta(coin).await {
                marks.push(CoinMark { coin: d.coin, mark: d.mark, positions: d.positions });
            }
        }
        Ok(ProtocolSnapshot {
            block: s.source.block.parse().unwrap_or(0),
            lp: raw_1e18_usd(&s.balances.lp),
            queue: raw_1e18_usd(&s.balances.queue),
            paper_rate: raw_1e18_usd(&s.paper.rate),
            paper_cliff: raw_1e18_usd(&s.paper.cliff),
            paper_cap: raw_1e18_usd(&s.paper.cap),
            paper_supply: raw_1e18_usd(&s.paper.supply),
            paper_tracked_lp: raw_1e18_usd(&s.paper.tracked_lp),
            marks,
            ..Default::default()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scales() {
        assert_eq!(raw_1e18_usd("100000000000000000000"), 100.0);
        assert_eq!(raw_1e18_usd("0"), 0.0);
        assert_eq!(raw_1e18_usd("5000000000000000000"), 5.0);
        assert_eq!(raw_1e18_usd(""), 0.0);
        assert_eq!(raw_1e18_usd("2000000000000000000000000"), 2_000_000.0);
    }

    #[test]
    fn summary_parse() {
        let j = r#"{"balances":{"lp":"4743385420157427688909112","queue":"0"},"paper":{"rate":"100000000000000000000","cliff":"2000000000000000000000000","cap":"5000000000000000000000000","supply":"4843667905311528181212326383","trackedLp":"4743385420157427688909112"},"source":{"block":"48202115"}}"#;
        let s: SummaryResp = serde_json::from_str(j).unwrap();
        assert_eq!(raw_1e18_usd(&s.balances.lp), 4743385.420157428);
        assert_eq!(raw_1e18_usd(&s.paper.rate), 100.0);
        assert_eq!(raw_1e18_usd(&s.paper.cliff), 2_000_000.0);
    }

    #[test]
    fn health_predicates() {
        let s = ProtocolSnapshot { queue: 0.0, paused: false, paper_cap: 5_000_000.0, paper_tracked_lp: 4_743_385.0, ..Default::default() };
        assert!(s.is_healthy());
        assert!((s.cap_distance() - 256615.0).abs() < 1.0);
        assert!(!ProtocolSnapshot { queue: 1.0, ..Default::default() }.is_healthy());
    }

    #[test]
    fn delta_parse() {
        let j = r#"{"delta":{"coin":"BTC","mark":83030.5,"markTs":1791668550879,"positionCount":3283,"range":0.01,"values":[]}}"#;
        let r: DeltaResp = serde_json::from_str(j).unwrap();
        assert_eq!(r.delta.coin, "BTC");
        assert_eq!(r.delta.positions, 3283);
    }
}
