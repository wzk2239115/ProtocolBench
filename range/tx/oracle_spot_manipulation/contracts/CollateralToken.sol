// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";

/// @title CollateralToken
/// @notice A stock OpenZeppelin ERC-20 (v5.1.0) with the constructor-mint
///         pattern. It is the collateral token of the lending pool (the token
///         users deposit as collateral). Standard EIP-20 semantics; nothing is
///         weakened or backdoored.
contract CollateralToken is ERC20 {
    constructor(
        string memory name_,
        string memory symbol_,
        uint256 initialSupply
    ) ERC20(name_, symbol_) {
        _mint(msg.sender, initialSupply);
    }
}
