// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/ERC20Permit.sol";

/// @notice tGt v2 (TheGambler) - Standard ERC20 + EIP-2612 Permit, fixed supply minted once.
/// Name: TheGambler
/// Symbol: tGt
/// Decimals: 18
contract TheGambler_tGtV2 is ERC20, ERC20Permit {
    uint256 public constant FIXED_SUPPLY = 1_000_000_000 * 1e18;

    constructor(address recipient)
        ERC20("TheGambler", "tGt")
        ERC20Permit("TheGambler")
    {
        require(recipient != address(0), "recipient=0");
        _mint(recipient, FIXED_SUPPLY);
    }
}
