// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";

/// @title AssetToken
/// @notice A stock OpenZeppelin ERC-20 (v5.1.0) with the ubiquitous
///         constructor-mint pattern (mint the initial supply to the deployer).
///         `transfer` / `approve` / `transferFrom` / `allowance` are exactly the
///         EIP-20 standard; nothing is weakened or backdoored. It serves as the
///         **collateral** token of the Cream-style lending pool — a plain,
///         hook-less ERC-20 whose transfers never invoke a recipient callback.
contract AssetToken is ERC20 {
    constructor(
        string memory name_,
        string memory symbol_,
        uint256 initialSupply
    ) ERC20(name_, symbol_) {
        _mint(msg.sender, initialSupply);
    }
}
