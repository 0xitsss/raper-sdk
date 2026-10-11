//! Alloy contract bindings (selectors verified against bytecode).

use alloy::sol;

sol! {
    #[sol(rpc)]
    contract Exchange {
        function collateralScale() view returns (uint256);
        function instrumentCount() view returns (uint256);
        function nextPositionId() view returns (uint256);
        function totalQueued() view returns (uint256);
        function totalLockedMargin() view returns (uint256);
        function liquidationFeeRate() view returns (uint256);
        function tradingPaused() view returns (uint256);
        function treasury() view returns (uint256);
        function balances(address) view returns (uint256);
        function positions(uint256) view returns (bool);
        function owner() view returns (address);
        function oracle() view returns (address);
        function liquidate(uint256 positionId);
        function close(uint256[] positionIds);
        function harvest(uint256 maxEntries);
    }
}

sol! {
    #[sol(rpc)]
    contract Wallet {
        function owner() view returns (address);
        function exchange() view returns (address);
        function sessionKeyManager() view returns (address);
    }
}

sol! {
    #[sol(rpc)]
    contract Paper {
        function decimals() view returns (uint8);
        function totalSupply() view returns (uint256);
        function balanceOf(address) view returns (uint256);
        function owner() view returns (address);
    }
}
