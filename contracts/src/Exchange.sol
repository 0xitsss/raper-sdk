// SPDX-License-Identifier: MIT
// Functional core of the Exchange, reconstructed from:
// - Heimdall decompile (checks order, storage effects, reverts)
// - live traces (param mapping: instrument/margin/leverage/side/deadline)
// - docs (haircut formula, fees, queue, bust buffer)
//
// NOT a byte-exact replica: storage layout/names are clean-room.
// Verified behaviors are marked [V], hypotheses [H].

pragma solidity ^0.8.20;

contract Exchange {
    // ---- roles ----
    address public owner;
    address public pauseGuardian;
    address public authorizedExecutor;
    address public authorizedKeeper;
    address public oracle;
    bool public tradingPaused;

    // ---- economics (1e18 fixed point, collateralScale 1e12 + USDC 6dp) ----
    uint256 public constant DEADBAND = 1e18 / 50000; // 0.2 bps
    uint256 public constant BASE_RATE = 0.10e18;
    uint256 public constant RATE_MULT = 15000e18;
    uint256 public constant REF_NOTIONAL = 100_000e18;
    uint256 public constant WIN_FEE = 0.02e18;
    uint256 public constant BUST_BUFFER = 0.0005e18; // 5 bps
    uint256 public constant STAKER_CAP = 5_000_000e18;

    uint256 public liquidationFeeRate = 0.02e18; // [V] live eth_call
    uint256 public nextPositionId = 1;

    struct Position {
        address user;
        uint32 instrument;
        uint256 margin;
        uint32 leverage;
        uint64 openedAt;
        bool isLong;
        uint256 entryPrice;
        bool closed;
    }

    mapping(uint256 => Position) public positions;
    mapping(address => uint256) public balances; // free collateral
    uint256 public payoutQueueLen;
    uint256 public lpCash;

    // posMult per instrument (BTC 814.598, ETH 483.979) [V]
    mapping(uint32 => uint256) public posMult;

    event Opened(uint256 indexed id, address indexed user, uint32 instrument, uint256 margin, uint32 leverage, bool isLong, uint256 entryPrice);
    event Closed(uint256 indexed id, int256 netPnl);

    modifier onlyExecutor() {
        require(msg.sender == authorizedExecutor, "executor only");
        _;
    }

    /// @notice Open leg (selector 0xec6783f0). [V] checks order from decompile.
    function openPosition(
        address user,
        uint32 instrument,
        uint256 margin,
        uint32 leverage,
        uint64 deadline,
        bool isLong
    ) external onlyExecutor returns (uint256 id) {
        require(!tradingPaused, "paused");
        require(leverage >= 1 && leverage <= 1000, "lev");
        require(block.timestamp <= deadline, "expired");
        uint256 notional = margin * leverage;
        require(notional >= 10_000e18 && notional <= 10_000_000e18 * 100, "notional"); // [H] on-chain cap observed above $10M
        uint256 entry = _bboMid(instrument);
        id = nextPositionId++;
        positions[id] = Position(user, instrument, margin, leverage, uint64(block.timestamp), isLong, entry, false);
        emit Opened(id, user, instrument, margin, leverage, isLong, entry);
    }

    /// @notice Close leg. Returns trader-side net PnL (negative = loss).
    function closePosition(uint256 id) external onlyExecutor returns (int256 net) {
        Position storage p = positions[id];
        require(!p.closed, "closed");
        p.closed = true;
        uint256 exitPx = _bboMid(p.instrument);
        (net,,) = _settle(p, exitPx);
        emit Closed(id, net);
    }

    /// @notice Bust check: adverse move >= 1/lev - buffer forfeits margin.
    function bustPrice(bool isLong, uint256 entry, uint32 lev) public pure returns (uint256) {
        uint256 frac = 1e18 / lev;
        if (isLong) return (entry * (1e18 - frac + BUST_BUFFER)) / 1e18;
        return (entry * (1e18 + frac - BUST_BUFFER)) / 1e18;
    }

    /// @notice Core economics: deadband -> impact haircut -> 2% win fee. [V] formula from docs.
    function _settle(Position memory p, uint256 exitPx) internal view returns (int256 net, uint256 scaled, bool bust) {
        uint256 notional = p.margin * p.leverage;
        int256 move = p.isLong
            ? int256(exitPx) - int256(p.entryPrice)
            : int256(p.entryPrice) - int256(exitPx);
        move = (move * 1e18) / int256(p.entryPrice);
        if (move < 0 && uint256(-move) >= 1e18 / p.leverage - BUST_BUFFER) {
            return (-int256(p.margin), 0, true);
        }
        if (move <= 0) return ((int256(p.margin) * move) / 1e18, 0, false);
        uint256 m = uint256(move) - DEADBAND;
        if (m == 0) return (0, 0, false);
        uint256 rawAdj = (notional * m) / 1e18;
        // scale = (1-base) / (1 + 1/(m*rateMult) + refNotional/(1e6*m*posMult))
        uint256 pm = posMult[p.instrument];
        if (pm == 0) pm = 814.598e18;
        uint256 scale = ((1e18 - BASE_RATE) * 1e18) /
            (1e18 + (1e36 / (m * RATE_MULT)) + (REF_NOTIONAL * 1e18) / (1e6 * m * pm / 1e18));
        scaled = (rawAdj * scale) / 1e18;
        net = int256((scaled * (1e18 - WIN_FEE)) / 1e18);
    }

    /// @notice BBO mid via oracle (delegatecall in the real contract).
    function _bboMid(uint32) internal view returns (uint256) {
        // Placeholder: real contract delegatecalls PriceOracle (0xcd61...)
        // which staticcalls HyperCore BBO precompile 0x080e.
        revert("oracle only");
    }
}
