// SPDX-License-Identifier: MIT
// Reconstructed user wallet: permissioned meta-tx executor.
// Verified behavior (wallet logic 0xe0bc...7262, 925-byte proxies):
// - per-caller permission bitmap (mapping slot keccak(caller, 0x20) & 0xff)
// - selector allowlist ("selector not allowed" — keys can open/close, never withdraw)
// - entry 0x251fb27d executes a signed batch against target (Exchange)
// - owner(), exchange(), initialize(addr x3), sessionKeyManager()

pragma solidity ^0.8.20;

contract UserWallet {
    error NotAuthorized();
    error SelectorNotAllowed();
    error BadSignature();
    error Expired();

    address public owner;
    address public exchange;
    address public sessionKeyManager;

    // caller => permission bitmap (low byte checked on entry)
    mapping(address => uint256) public permissions;

    event Executed(address indexed target, bytes4 selector, bool ok);

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotAuthorized();
        _;
    }

    function initialize(address owner_, address exchange_, address sessionKeyManager_) external {
        require(owner == address(0), "init");
        owner = owner_;
        exchange = exchange_;
        sessionKeyManager = sessionKeyManager_;
    }

    /// @notice Register/update a session key bitmask (owner or sessionKeyManager).
    function setKeyPermissions(address key, uint256 bitmap) external {
        if (msg.sender != owner && msg.sender != sessionKeyManager) revert NotAuthorized();
        permissions[key] = bitmap;
    }

    /// @notice Meta-tx entry (selector 0x251fb27d on the real contract).
    /// @dev Packs: target + tightly-packed subcalls (len-prefixed) + deadline + ECDSA sig.
    /// Exact signature preimage (EIP-712 vs raw keccak) unverified — see research notes.
    function execute(
        address target,
        bytes[] calldata subcalls,
        uint64 deadline,
        bytes calldata sig
    ) external returns (bytes[] memory results) {
        if (permissions[msg.sender] & 0xff == 0) revert NotAuthorized();
        if (block.timestamp > deadline) revert Expired();
        // NOTE: real contract verifies ECDSA over EIP-712-ish digest here.
        if (!_checkSig(target, subcalls, deadline, sig)) revert BadSignature();
        results = new bytes[](subcalls.length);
        for (uint256 i = 0; i < subcalls.length; i++) {
            if (!_selectorAllowed(bytes4(subcalls[i]))) revert SelectorNotAllowed();
            (bool ok, bytes memory ret) = target.call(subcalls[i]);
            results[i] = ret;
            emit Executed(target, bytes4(subcalls[i]), ok);
            require(ok, "subcall failed");
        }
    }

    function _checkSig(
        address,
        bytes[] calldata,
        uint64,
        bytes calldata
    ) internal pure returns (bool) {
        // Placeholder: real logic recovers signer and matches permissions bitmap.
        return true;
    }

    function _selectorAllowed(bytes4) internal pure returns (bool) {
        // Placeholder: real contract holds per-key allowlist (open/close only).
        return true;
    }

    function transferOwnership(address to) external onlyOwner {
        owner = to;
    }
}
