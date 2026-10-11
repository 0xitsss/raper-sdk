// SPDX-License-Identifier: MIT
// Reconstructed PAPER: fair-launch LP fee-claim token.
// Verified: standard ERC20 + mint(address,uint256) gated (reverts for strangers),
// owner() = protocol owner. Proxy -> logic 0x433b...735bb4.

pragma solidity ^0.8.20;

contract PaperToken {
    error NotMinter();

    string public name = "PAPER";
    string public symbol = "PAPER";
    uint8 public decimals = 18;

    uint256 public totalSupply;
    address public owner;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    mapping(address => bool) public minters;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function initialize(address owner_) external {
        require(owner == address(0), "init");
        owner = owner_;
    }

    function setMinter(address m, bool ok) external onlyOwner {
        minters[m] = ok;
    }

    /// @notice Mint on realized user losses. Only protocol contracts.
    function mint(address to, uint256 amount) external {
        if (!minters[msg.sender]) revert NotMinter();
        unchecked {
            totalSupply += amount;
            balanceOf[to] += amount;
        }
        emit Transfer(address(0), to, amount);
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        require(balanceOf[msg.sender] >= amount, "bal");
        unchecked {
            balanceOf[msg.sender] -= amount;
            balanceOf[to] += amount;
        }
        emit Transfer(msg.sender, to, amount);
        return true;
    }

    function approve(address sp, uint256 amount) external returns (bool) {
        allowance[msg.sender][sp] = amount;
        emit Approval(msg.sender, sp, amount);
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        uint256 a = allowance[from][msg.sender];
        require(a >= amount && balanceOf[from] >= amount, "allow/bal");
        unchecked {
            if (a != type(uint256).max) allowance[from][msg.sender] = a - amount;
            balanceOf[from] -= amount;
            balanceOf[to] += amount;
        }
        emit Transfer(from, to, amount);
        return true;
    }

    function transferOwnership(address to) external onlyOwner {
        owner = to;
    }
}
