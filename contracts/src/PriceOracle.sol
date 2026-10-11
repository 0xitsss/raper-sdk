// SPDX-License-Identifier: MIT
// Reconstructed PriceOracle: reads HyperCore BBO via precompile 0x080e.
// Verified behavior: price = (bid + ask) / 2, revert on bid==0 or ask<bid.
// No TWAP / deviation breaker / lookback (confirmed by audit).

pragma solidity ^0.8.20;

interface IBboPrecompile {
    function bbo(uint32 asset) external view returns (uint64 bid, uint64 ask);
}

contract PriceOracle {
    // HyperCore BBO precompile (HyperEVM 999).
    address internal constant BBO = 0x000000000000000000000000000000000000080e;

    error CrossedMarket();
    error EmptyBook();

    /// @notice Mid price for HyperCore perp `asset` (BTC=0, ETH=1).
    function mark(uint32 asset) external view returns (uint256 mid) {
        (uint64 bid, uint64 ask) = IBboPrecompile(BBO).bbo(asset);
        if (bid == 0) revert EmptyBook();
        if (ask < bid) revert CrossedMarket();
        unchecked {
            mid = (uint256(bid) + uint256(ask)) / 2;
        }
    }

    /// @notice Raw BBO tuple (for analytics / frontrun detection).
    function bbo(uint32 asset) external view returns (uint64 bid, uint64 ask) {
        return IBboPrecompile(BBO).bbo(asset);
    }
}
