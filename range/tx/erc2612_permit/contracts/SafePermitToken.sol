// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {ERC20Permit} from "@openzeppelin/contracts/token/ERC20/extensions/ERC20Permit.sol";

/// @title SafePermitToken
/// @notice The fixed ERC-2612 variant: OpenZeppelin's `ERC20Permit` (v5.1.0)
///         which inherits `EIP712` and builds the domain separator from
///         `block.chainid` AND `address(this)` — the EIP-712 / OZ
///         `_domainSeparator` mitigation. Because the domain is bound to the
///         verifying contract address, a `permit` signature valid for one
///         deployment is NOT valid for another: cross-deployment replay fails.
///
/// @dev This is the stock, documented mitigation. No backdoor. Used for the
///      negative test.
contract SafePermitToken is ERC20Permit {
    constructor(
        string memory name_,
        string memory symbol_,
        uint256 initialSupply
    ) ERC20(name_, symbol_) ERC20Permit(name_) {
        _mint(msg.sender, initialSupply);
    }
}
