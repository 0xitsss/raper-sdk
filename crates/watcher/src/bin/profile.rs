//! Crowd profiler: public tape stats (opens/closes/net per side).
//!
//! Usage: profile [--base URL]

mod common;

use std::collections::HashMap;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let base = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "https://exchange.papertrade.xyz".into());
    let tape = common::fetch_recent(&base).await?;
    println!("tape events: {}", tape.len());
    let mut opens = 0;
    let mut closes = 0;
    let mut pnl = 0.0;
    let mut by_side: HashMap<String, (i32, f64)> = HashMap::new();
    for e in &tape {
        if e.kind == "open" {
            opens += 1;
        } else if e.kind == "close" {
            closes += 1;
            if let Some(p) = e.pnl {
                pnl += p;
                let s = by_side.entry(e.side.clone()).or_insert((0, 0.0));
                s.0 += 1;
                s.1 += p;
            }
        }
    }
    println!("opens={} closes={} crowd_net={:+.2}", opens, closes, pnl);
    for (side, (n, p)) in &by_side {
        println!("  close {:5} n={:3} net={:+.2}", side, n, p);
    }
    Ok(())
}
