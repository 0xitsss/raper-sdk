//! Minimal JSON-RPC client (reqwest, no alloy needed for simple calls).

use anyhow::Result;

#[derive(Clone)]
pub struct Rpc {
    url: String,
    client: reqwest::Client,
}

impl Rpc {
    pub fn new(url: &str) -> Result<Self> {
        Ok(Self {
            url: url.into(),
            client: reqwest::Client::builder()
                .user_agent("raper-sdk/0.1")
                .timeout(std::time::Duration::from_secs(30))
                .build()?,
        })
    }

    pub async fn call(&self, method: &str, params: serde_json::Value) -> Result<serde_json::Value> {
        let body = serde_json::json!({"jsonrpc":"2.0","id":1,"method":method,"params":params});
        let resp: serde_json::Value = self.client.post(&self.url).json(&body).send().await?.error_for_status()?.json().await?;
        resp.get("result").cloned().ok_or_else(|| anyhow::anyhow!("no result: {}", resp))
    }

    pub async fn block_number(&self) -> Result<u64> {
        let v = self.call("eth_blockNumber", serde_json::json!([])).await?;
        Ok(u64::from_str_radix(v.as_str().unwrap_or("0x0").trim_start_matches("0x"), 16).unwrap_or(0))
    }

    pub async fn eth_call(&self, to: &str, data: &str) -> Result<String> {
        let v = self.call("eth_call", serde_json::json!([{"to": to, "data": data}, "latest"])).await?;
        Ok(v.as_str().unwrap_or("0x").to_string())
    }

    pub async fn get_code(&self, addr: &str) -> Result<String> {
        let v = self.call("eth_getCode", serde_json::json!([addr, "latest"])).await?;
        Ok(v.as_str().unwrap_or("0x").to_string())
    }
}

/// keccak256 first 4 bytes hex (function selector).
pub fn selector(sig: &str) -> String {
    use sha3::{Digest, Keccak256};
    let mut h = Keccak256::new();
    h.update(sig.as_bytes());
    hex::encode(&h.finalize()[..4])
}
