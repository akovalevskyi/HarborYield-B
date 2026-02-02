// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

/// @notice Testnet stablecoin: USDx (USDC-like 6 decimals) + faucet + owner mint
contract USDx is ERC20, Ownable {
    uint8 private constant _DECIMALS = 6;

    // Faucet settings
    uint256 public faucetAmount = 1_000 * 10 ** _DECIMALS; // 1,000 USDx
    uint256 public faucetCooldown = 60; // seconds
    mapping(address => uint256) public lastFaucetAt;

    constructor(address initialOwner) ERC20("USDx", "USDx") Ownable(initialOwner) {}

    function decimals() public pure override returns (uint8) {
        return _DECIMALS;
    }

    /// @notice Mint small amount to caller with cooldown
    function faucet() external {
        uint256 last = lastFaucetAt[msg.sender];
        require(block.timestamp >= last + faucetCooldown, "faucet cooldown");
        lastFaucetAt[msg.sender] = block.timestamp;
        _mint(msg.sender, faucetAmount);
    }

    /// @notice Mint small amount to any address with cooldown (useful for demo)
    function faucetTo(address to) external {
        uint256 last = lastFaucetAt[to];
        require(block.timestamp >= last + faucetCooldown, "faucet cooldown");
        lastFaucetAt[to] = block.timestamp;
        _mint(to, faucetAmount);
    }

    /// @notice Admin mint (vault inventory / relayer, etc.)
    function ownerMint(address to, uint256 amount) external onlyOwner {
        _mint(to, amount);
    }

    /// @notice Admin can tune faucet params
    function setFaucet(uint256 amount, uint256 cooldownSeconds) external onlyOwner {
        faucetAmount = amount;
        faucetCooldown = cooldownSeconds;
    }
}
