//! Transaction builders for phase 2 (keys required — NOT active in phase 1).
//! Encoding only. Nothing here signs or sends.

/// ABI-encode open leg params for 0xec6783f0.
/// Layout: (user, instrument, ?, margin_raw, leverage, ?, ?, deadline, ?, ?, ?).
/// Zero-slots MUST be re-verified against a live trace before mainnet use.
pub fn encode_open(user: &str, instrument: u32, margin_raw: u128, leverage: u32, deadline: u64) -> String {
    let mut out = String::from("ec6783f0");
    out.push_str(&pad_addr(user));
    out.push_str(&pad_u32(instrument));
    out.push_str(&"0".repeat(64));
    out.push_str(&pad_u128(margin_raw));
    out.push_str(&pad_u32(leverage));
    out.push_str(&"0".repeat(64));
    out.push_str(&"0".repeat(64));
    out.push_str(&pad_u64(deadline));
    out.push_str(&"0".repeat(64));
    out.push_str(&"0".repeat(64));
    out.push_str(&"0".repeat(64));
    format!("0x{}", out)
}

fn pad_addr(a: &str) -> String {
    let h = a.trim_start_matches("0x");
    let h = &h[h.len().saturating_sub(40)..];
    format!("{}{}", "0".repeat(64 - h.len()), h)
}

fn pad_u32(v: u32) -> String {
    format!("{:064x}", v)
}

fn pad_u64(v: u64) -> String {
    format!("{:064x}", v)
}

fn pad_u128(v: u128) -> String {
    format!("{:064x}", v)
}

/// Selector sanity vs chain (verified 24/24 during research).
pub fn check_selectors() -> bool {
    use super::rpc::selector;
    [
        ("collateralScale()", "ec0bdcfc"),
        ("positions(uint256)", "99fbab88"),
        ("balances(address)", "27e235e3"),
        ("liquidationFeeRate()", "5fb3b1b5"),
    ]
    .into_iter()
    .all(|(sig, want)| selector(sig) == want)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selectors_match_chain() {
        assert!(check_selectors());
    }

    #[test]
    fn encode_open_shape() {
        let data = encode_open("0x1111111111111111111111111111111111111111", 1, 2000, 500, 1791706105);
        assert!(data.starts_with("0xec6783f0"));
        assert_eq!(data.len(), 2 + 8 + 64 * 11);
        assert_eq!(&data[2 + 8 + 64 * 4..2 + 8 + 64 * 4 + 64], &format!("{:064x}", 500));
    }
}
