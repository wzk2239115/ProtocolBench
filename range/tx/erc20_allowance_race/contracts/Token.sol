// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";

/// @title Token
/// @notice A stock OpenZeppelin ERC-20 (v5.1.0). The ONLY addition is the
///         ubiquitous constructor-mint pattern used by every fixed-supply
///         token (mint the initial supply to the deployer). The `transfer`,
///         `approve`, `transferFrom` and `allowance` semantics are exactly
///         those of the EIP-20 standard; nothing is weakened or backdoored.
///
/// @dev The standard defines the approve/transferFrom front-running race in
///      its own "Security Considerations" section; this contract implements
///      the standard faithfully, so that documented race is live and real.
contract Token is ERC20 {
    constructor(
        string memory name_,
        string memory symbol_,
        uint256 initialSupply
    ) ERC20(name_, symbol_) {
        _mint(msg.sender, initialSupply);
    }
}
