//! Live-принтер публичной ленты Papertrade (только чтение).
//!
//! Поллит `GET {base}/query/protocol/trades/recent` каждые N секунд
//! (HTTP-клиент и Referer — в `common::fetch_recent`, см. `common.rs`),
//! печатает только НОВЫЕ события (дедуп по `seq`).
//!
//! Usage: tape [--base URL] [--interval SEC]
//!
//! Строка события: kind, side, instrument, lev, notional, entry/exit/pnl,
//! короткий адрес кошелька (первые 6 + последние 4 символа, только из сети).
//! Каждые 60с — сводка окна: opens/closes/crowd_net (сумма pnl закрытий).

mod common;

use std::collections::HashSet;
use std::time::Duration;

const DEFAULT_BASE: &str = "https://exchange.papertrade.xyz";
const DEFAULT_INTERVAL_SECS: u64 = 5;
const SUMMARY_WINDOW_SECS: u64 = 60;

fn parse_args() -> (String, u64) {
    let mut base = DEFAULT_BASE.to_string();
    let mut interval = DEFAULT_INTERVAL_SECS;
    let mut positional: Vec<String> = Vec::new();
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        if a == "--base" {
            if let Some(v) = args.get(i + 1) {
                base = v.clone();
                i += 1;
            }
        } else if let Some(v) = a.strip_prefix("--base=") {
            base = v.to_string();
        } else if a == "--interval" {
            if let Some(v) = args.get(i + 1) {
                if let Ok(n) = v.parse::<u64>() {
                    interval = n;
                }
                i += 1;
            }
        } else if let Some(v) = a.strip_prefix("--interval=") {
            if let Ok(n) = v.parse::<u64>() {
                interval = n;
            }
        } else if a == "-h" || a == "--help" {
            eprintln!("Usage: tape [--base URL] [--interval SEC]");
            std::process::exit(0);
        } else if !a.starts_with('-') {
            positional.push(a.to_string());
        }
        i += 1;
    }
    // Совместимость с profile: голый первый аргумент = base, если --base не задан.
    if base == DEFAULT_BASE {
        if let Some(p) = positional.into_iter().next() {
            base = p;
        }
    }
    if interval == 0 {
        interval = 1;
    }
    (base, interval)
}

/// Короткий адрес только из сетевых данных: первые 6 + последние 4 символа.
fn short_wallet(w: &str) -> String {
    let chars: Vec<char> = w.chars().collect();
    if chars.len() <= 10 {
        return w.to_string();
    }
    let head: String = chars[..6].iter().collect();
    let tail: String = chars[chars.len() - 4..].iter().collect();
    format!("{head}..{tail}")
}

fn print_event(e: &common::TradeEvent) {
    let mut extra = String::new();
    if let Some(v) = e.entry {
        extra.push_str(&format!(" entry={v}"));
    }
    if let Some(v) = e.exit {
        extra.push_str(&format!(" exit={v}"));
    }
    if let Some(v) = e.pnl {
        extra.push_str(&format!(" pnl={v:+.2}"));
    }
    println!(
        "{} {} {} {}x notional=${:.2}{} wallet={} seq={} ts={}",
        e.kind,
        e.side,
        e.instrument,
        e.leverage,
        e.notional,
        extra,
        short_wallet(&e.wallet),
        e.seq,
        e.ts
    );
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let (base, interval_secs) = parse_args();
    let interval = Duration::from_secs(interval_secs);
    println!(
        "tape: polling {}/query/protocol/trades/recent every {}s",
        base.trim_end_matches('/'),
        interval_secs
    );

    let mut seen: HashSet<String> = HashSet::new();
    let mut opens: u64 = 0;
    let mut closes: u64 = 0;
    let mut crowd_net: f64 = 0.0;
    let mut window_start = std::time::Instant::now();

    loop {
        match common::fetch_recent(&base).await {
            Ok(events) => {
                let mut fresh: Vec<_> =
                    events.into_iter().filter(|e| !seen.contains(&e.seq)).collect();
                fresh.sort_by(|a, b| a.ts.cmp(&b.ts).then_with(|| a.seq.cmp(&b.seq)));
                for e in &fresh {
                    seen.insert(e.seq.clone());
                    if e.kind == "open" {
                        opens += 1;
                    } else if e.kind == "close" {
                        closes += 1;
                        if let Some(p) = e.pnl {
                            crowd_net += p;
                        }
                    }
                    print_event(e);
                }
            }
            Err(e) => eprintln!("fetch error: {e:#}"),
        }
        if window_start.elapsed() >= Duration::from_secs(SUMMARY_WINDOW_SECS) {
            println!("--- 60s summary: opens={opens} closes={closes} crowd_net={crowd_net:+.2} ---");
            opens = 0;
            closes = 0;
            crowd_net = 0.0;
            window_start = std::time::Instant::now();
        }
        tokio::time::sleep(interval).await;
    }
}
