// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";

/// @title RewardToken
/// @notice A stock OpenZeppelin ERC-20 (v5.1.0) with a fixed supply minted to
///         the deployer. Used as the reward currency paid out by the `Recipient`
///         faucet. Unmodified standard semantics; nothing weakened or backdoored.
contract RewardToken is ERC20 {
    constructor(
        string memory name_,
        string memory symbol_,
        uint256 initialSupply
    ) ERC20(name_, symbol_) {
        _mint(msg.sender, initialSupply);
    }
}
