// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ERC777} from "@erc777/contracts/token/ERC777/ERC777.sol";

/// @title ImBTC777
/// @notice A real ERC-777 token built on the **unmodified** OpenZeppelin
///         ERC777 v4.9.6 implementation. The ONLY addition is the ubiquitous
///         constructor-mint pattern used by every fixed-supply token (mint the
///         initial supply to the deployer). The `send`/`transfer`/`transferFrom`
///         semantics are exactly the EIP-777 standard, including the
///         `tokensToSend` / `tokensReceived` hooks discovered through the global
///         ERC-1820 registry. Nothing is weakened or backdoored.
///
/// @dev This mirrors the imBTC token (an ERC-777 token) that was at the centre
///      of the April 2020 reentrancy incidents. EIP-777 mandates that the
///      `tokensToSend` hook on the sender is invoked _before_ the token state is
///      updated (see OZ ERC777._send: `_callTokensToSend` runs before `_move`),
///      which is the property a balance-priced AMM without a reentrancy guard
///      composes badly with.
contract ImBTC777 is ERC777 {
    constructor(uint256 initialSupply, address[] memory defaultOperators)
        ERC777("imBTC", "imBTC", defaultOperators)
    {
        // requireReceptionAck = false: the deployer is an EOA; mirrors the
        // standard fixed-supply mint pattern.
        _mint(msg.sender, initialSupply, "", "", false);
    }
}
