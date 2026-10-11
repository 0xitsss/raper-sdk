//! Decode a 0x251fb27d meta-tx from argv hex.
//! Run: cargo run -p raper-sdk --example decode -- 0x251fb27d...

use decoder::{classify, describe_hex, Leg};

fn main() {
    let hex = std::env::args().nth(1).unwrap_or_default();
    if hex.is_empty() {
        eprintln!("usage: decode 0x...");
        std::process::exit(2);
    }
    println!("{}", describe_hex(&hex));
    match classify(&hex) {
        Leg::Open(o) => println!("OPEN inst={} margin={} lev={} user={} w2={} w8={}", o.instrument, o.margin_raw, o.leverage, o.user, o.w2, o.w8),
        Leg::Close { anchor, params } => println!("CLOSE {} user={}", anchor, params.f0_user),
        Leg::Unknown { reason } => println!("UNKNOWN: {}", reason),
    }
}
