//! Papertrade economics simulator (isolated positions, BBO-mid execution).
//!
//! Port of `internal/paper/paper.go`: execution at BBO mid with zero
//! slippage/spread/funding. Wins take a deadband + impact-scale haircut and a
//! 2% win fee; losses pass through 1:1 with no haircut; an adverse move at or
//! past `1/lev − 5bps` busts the full margin.

/// Deadband: a gain counts only as if the exit were worse by `entry/50000`
/// (0.2 bps). Dust at/under this move pays out zero.
pub const DEADBAND_RATE: f64 = 1.0 / 50000.0;
/// Base haircut in the impact-scale numerator (`1 - 0.10`).
pub const BASE_RATE: f64 = 0.10;
/// Rate multiplier in impact `term1 = 1/(move*15000)`.
pub const RATE_MULTIPLIER: f64 = 15000.0;
/// Reference notional in impact `term2 = 100000/(1e6*move*posMult)`.
pub const IMPACT_REF: f64 = 100000.0;
/// Fee taken on the scaled win (2%).
pub const WIN_FEE_RATE: f64 = 0.02;
/// Bust buffer toward entry vs the zero-equity move (~5 bps).
pub const BUST_BUFFER: f64 = 0.0005;
/// Max position notional ($10M). Reference only: neither the Go source nor
/// this port enforces it inside the payout math.
pub const MAX_NOTIONAL: f64 = 10_000_000.0;

/// Position-size multiplier from the asymmetric-impact docs.
///
/// `ETH` uses its own constant; every other symbol falls back to the `BTC`
/// default. Exact, case-sensitive match — 1:1 with the Go reference.
pub fn pos_mult(symbol: &str) -> f64 {
    if symbol == "ETH" {
        483.979
    } else {
        814.598 // BTC default
    }
}

/// Trader-side net PnL for closing a paper position.
///
/// `side`: `+1` long, `-1` short. `margin > 0`, `lev > 0`, `entry > 0`.
///
/// Returns `(net, scaled, bust)`:
/// - bust: adverse move at/past `1/lev − BUST_BUFFER` forfeits the whole
///   margin → `(-margin, 0.0, true)`.
/// - loss or flat (`raw <= 0`): no haircut, 1:1 → `(raw, 0.0, false)`.
/// - dust (`move − DEADBAND_RATE <= 0`): `(0.0, 0.0, false)`.
/// - win: deadband-adjusted gain × impact scale × (1 − 2% fee).
pub fn net_payout(
    symbol: &str,
    side: i8,
    entry: f64,
    exit: f64,
    margin: f64,
    lev: f64,
) -> (f64, f64, bool) {
    let s = f64::from(side);
    let mv = (exit - entry) / entry * s;
    // Hard bust: full margin forfeit past the buffer.
    let liq_move = 1.0 / lev - BUST_BUFFER;
    if mv < 0.0 && -mv >= liq_move {
        return (-margin, 0.0, true);
    }
    let notional = margin * lev;
    let raw = mv * notional;
    if raw <= 0.0 {
        return (raw, 0.0, false);
    }
    // Deadband: gain measured as if the exit were worse by entry/50000.
    let db_move = mv - DEADBAND_RATE;
    if db_move <= 0.0 {
        return (0.0, 0.0, false);
    }
    let raw_adj = db_move * notional;
    let term1 = 1.0 / (db_move * RATE_MULTIPLIER);
    let term2 = IMPACT_REF / (1e6 * db_move * pos_mult(symbol));
    let scale = (1.0 - BASE_RATE) / (1.0 + term1 + term2);
    let scaled = raw_adj * scale;
    let net = scaled * (1.0 - WIN_FEE_RATE);
    (net, scaled, false)
}

/// Hard-bust (liquidation) price of an isolated position.
///
/// Long: `entry*(1 − 1/lev + buffer)`; short (any `side <= 0`, as in Go):
/// `entry*(1 + 1/lev − buffer)`.
pub fn bust_price(side: i8, entry: f64, lev: f64) -> f64 {
    if side > 0 {
        entry * (1.0 - 1.0 / lev + BUST_BUFFER)
    } else {
        entry * (1.0 + 1.0 / lev - BUST_BUFFER)
    }
}

/// An open paper position held by [`Sim`].
#[derive(Debug, Clone, PartialEq)]
pub struct Position {
    /// Market symbol (`"BTC"`, `"ETH"`, …).
    pub symbol: String,
    /// `+1` long, `-1` short.
    pub side: i8,
    /// Fill price at open.
    pub entry: f64,
    /// Isolated margin locked for this trade.
    pub margin: f64,
    /// Leverage.
    pub lev: f64,
}

/// Minimal paper-run simulator.
///
/// Accounting: opening a position only records it — equity moves solely on
/// [`Sim::close`] by the [`net_payout`] result (`equity += net`, bust nets
/// `-margin`). `trades` counts closed trades.
#[derive(Debug, Default)]
pub struct Sim {
    /// Current paper equity (grows/shrinks by closed-trade net PnL).
    pub equity: f64,
    /// Number of closed trades.
    pub trades: u64,
    open: Vec<Position>,
}

impl Sim {
    /// New simulator with `equity` starting capital and no open positions.
    pub fn new(equity: f64) -> Self {
        Self {
            equity,
            trades: 0,
            open: Vec::new(),
        }
    }

    /// Record a new open position; returns its id for [`Sim::close`].
    pub fn open(&mut self, symbol: &str, side: i8, entry: f64, margin: f64, lev: f64) -> usize {
        self.open.push(Position {
            symbol: symbol.to_string(),
            side,
            entry,
            margin,
            lev,
        });
        self.open.len() - 1
    }

    /// Close position `id` at `exit`, settle via [`net_payout`].
    ///
    /// Returns `(net, scaled, bust)`; adds `net` to equity, bumps `trades`,
    /// and removes the position (swap-remove, so ids of other open positions
    /// may change).
    ///
    /// Panics on an unknown `id`.
    pub fn close(&mut self, id: usize, exit: f64) -> (f64, f64, bool) {
        if id >= self.open.len() {
            panic!("paper::Sim::close: unknown position id {id}");
        }
        let p = self.open.swap_remove(id);
        let (net, scaled, bust) = net_payout(&p.symbol, p.side, p.entry, exit, p.margin, p.lev);
        self.equity += net;
        self.trades += 1;
        (net, scaled, bust)
    }

    /// Number of currently open positions.
    pub fn open_count(&self) -> usize {
        self.open.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ENTRY: f64 = 100_000.0;
    const MARGIN: f64 = 1_000.0;
    const LEV: f64 = 10.0;
    const NOTIONAL: f64 = MARGIN * LEV; // 10_000

    fn approx(a: f64, b: f64, eps: f64) -> bool {
        (a - b).abs() <= eps
    }

    #[test]
    fn loss_long_passes_through_without_haircut() {
        // -1% on 10x: raw = -0.01 * 10_000 = -100, no bust (0.01 < 0.0995).
        let (net, scaled, bust) = net_payout("BTC", 1, ENTRY, 99_000.0, MARGIN, LEV);
        assert!(!bust);
        assert_eq!(scaled, 0.0);
        assert!(approx(net, -100.0, 1e-9), "net={net}");
    }

    #[test]
    fn loss_short_passes_through_without_haircut() {
        // Short, +1% against: raw = -100, 1:1.
        let (net, scaled, bust) = net_payout("BTC", -1, ENTRY, 101_000.0, MARGIN, LEV);
        assert!(!bust);
        assert_eq!(scaled, 0.0);
        assert!(approx(net, -100.0, 1e-9), "net={net}");
    }

    #[test]
    fn flat_exit_pays_zero() {
        // Go boundary: move = 0 -> raw = 0 -> (raw, 0, false).
        let (net, scaled, bust) = net_payout("BTC", 1, ENTRY, ENTRY, MARGIN, LEV);
        assert!(!bust);
        assert_eq!(net, 0.0);
        assert_eq!(scaled, 0.0);
    }

    #[test]
    fn win_is_cut_below_raw_and_pays_fee() {
        // +1% long on 10x: raw = +100.
        let (net, scaled, bust) = net_payout("BTC", 1, ENTRY, 101_000.0, MARGIN, LEV);
        assert!(!bust);
        assert!(scaled > 0.0 && net > 0.0);
        assert!(net < scaled, "2% win fee: net={net} scaled={scaled}");
        assert!(approx(net, scaled * (1.0 - WIN_FEE_RATE), 1e-9));
        assert!(
            scaled < NOTIONAL * 0.01,
            "impact scale must bite: scaled={scaled}"
        );
        assert!(net < 100.0, "win must be far below raw 100: net={net}");
    }

    #[test]
    fn dust_below_deadband_pays_zero() {
        // +1 unit on 100k = 0.1 bps < 0.2 bps deadband.
        let (net, scaled, bust) = net_payout("BTC", 1, ENTRY, ENTRY + 1.0, MARGIN, LEV);
        assert!(!bust);
        assert_eq!(net, 0.0);
        assert_eq!(scaled, 0.0);
    }

    #[test]
    fn deadband_boundary_pays_effectively_zero_but_above_pays() {
        // Exactly at the deadband the payout is ~0 either way the fp
        // rounding falls (win-branch net would be ~1e-17).
        let edge = ENTRY * (1.0 + DEADBAND_RATE);
        let (net, _, bust) = net_payout("BTC", 1, ENTRY, edge, MARGIN, LEV);
        assert!(!bust);
        assert!(net.abs() < 1e-6, "net={net}");
        // 2x past the deadband: db_move = +2e-5 > 0 -> real (small) win.
        let above = ENTRY * (1.0 + 2.0 * DEADBAND_RATE);
        let (net, scaled, bust) = net_payout("BTC", 1, ENTRY, above, MARGIN, LEV);
        assert!(!bust);
        assert!(net > 0.0 && scaled > 0.0, "net={net} scaled={scaled}");
    }

    #[test]
    fn bust_long_minus10pct_at_10x_forfeits_margin() {
        let (net, scaled, bust) = net_payout("BTC", 1, ENTRY, 90_000.0, 500.0, 10.0);
        assert!(bust);
        assert!(approx(net, -500.0, 1e-9), "net={net}");
        assert_eq!(scaled, 0.0);
    }

    #[test]
    fn bust_short_plus10pct_at_10x_forfeits_margin() {
        let (net, scaled, bust) = net_payout("BTC", -1, ENTRY, 110_000.0, 500.0, 10.0);
        assert!(bust);
        assert!(approx(net, -500.0, 1e-9), "net={net}");
        assert_eq!(scaled, 0.0);
    }

    #[test]
    fn bust_threshold_is_inclusive_and_inside_is_full_loss() {
        // Go boundary: adverse move == 1/lev - buffer busts (inclusive >=).
        let liq = 1.0 / LEV - BUST_BUFFER; // 0.0995
        let at_edge = ENTRY * (1.0 - liq);
        let (net, _, bust) = net_payout("BTC", 1, ENTRY, at_edge, MARGIN, LEV);
        assert!(bust, "edge exit={at_edge} must bust");
        assert!(approx(net, -MARGIN, 1e-6), "net={net}");
        // Just inside: -9.9% -> no bust, plain 1:1 loss of 990.
        let (net, scaled, bust) = net_payout("BTC", 1, ENTRY, 90_100.0, MARGIN, LEV);
        assert!(!bust);
        assert_eq!(scaled, 0.0);
        assert!(approx(net, -990.0, 1e-6), "net={net}");
    }

    #[test]
    fn bust_price_matches_go_formulas() {
        assert!(approx(bust_price(1, ENTRY, 10.0), 90_050.0, 1e-9));
        assert!(approx(bust_price(-1, ENTRY, 10.0), 109_950.0, 1e-9));
        // bust_price is consistent with the bust trigger.
        let bp = bust_price(1, ENTRY, LEV);
        let (_, _, bust) = net_payout("BTC", 1, ENTRY, bp, MARGIN, LEV);
        assert!(bust);
        let bp = bust_price(-1, ENTRY, LEV);
        let (_, _, bust) = net_payout("BTC", -1, ENTRY, bp, MARGIN, LEV);
        assert!(bust);
    }

    #[test]
    fn eth_scales_harder_than_btc_and_unknown_falls_back_to_btc() {
        let win_exit = 101_000.0;
        let (net_btc, _, _) = net_payout("BTC", 1, ENTRY, win_exit, MARGIN, LEV);
        let (net_eth, _, _) = net_payout("ETH", 1, ENTRY, win_exit, MARGIN, LEV);
        assert!(net_eth > 0.0);
        assert!(
            net_eth < net_btc,
            "smaller ETH mult -> bigger term2 -> smaller payout: eth={net_eth} btc={net_btc}"
        );
        let (net_sol, _, _) = net_payout("SOL", 1, ENTRY, win_exit, MARGIN, LEV);
        assert_eq!(net_sol, net_btc);
    }

    #[test]
    fn sim_settles_win_and_bust_into_equity() {
        let mut sim = Sim::new(10_000.0);
        let id = sim.open("BTC", 1, ENTRY, MARGIN, LEV);
        assert_eq!(sim.open_count(), 1);
        let (net, _, bust) = sim.close(id, 101_000.0);
        assert!(!bust && net > 0.0);
        assert!(approx(sim.equity, 10_000.0 + net, 1e-9));
        assert_eq!(sim.trades, 1);
        assert_eq!(sim.open_count(), 0);

        let id = sim.open("BTC", 1, ENTRY, 500.0, 10.0);
        let before = sim.equity;
        let (net, _, bust) = sim.close(id, 90_000.0);
        assert!(bust);
        assert!(approx(net, -500.0, 1e-9));
        assert!(approx(sim.equity, before - 500.0, 1e-9));
        assert_eq!(sim.trades, 2);
    }

    #[test]
    #[should_panic(expected = "unknown position id")]
    fn sim_close_unknown_id_panics() {
        Sim::new(1.0).close(0, ENTRY);
    }
}
