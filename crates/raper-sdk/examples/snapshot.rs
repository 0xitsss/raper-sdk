//! Print a unified protocol snapshot (REST + chain).
//! Run: cargo run -p raper-sdk --example snapshot

use raper_sdk::metrics::MetricsPoller;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let p = MetricsPoller::new("https://exchange.papertrade.xyz")?;
    let s = p.snapshot_once().await?;
    println!("LP ${:.0}  queue ${:.0}  healthy={}", s.lp, s.queue, s.is_healthy());
    println!("PAPER rate={} cliff={} cap={} supply={}", s.paper_rate, s.paper_cliff, s.paper_cap, s.paper_supply);
    println!("cap_distance=${:.0}", s.cap_distance());
    for m in &s.marks {
        println!("{} mark={} positions={}", m.coin, m.mark, m.positions);
    }
    Ok(())
}
