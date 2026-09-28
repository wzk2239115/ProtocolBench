// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {DAOToken} from "./DAOToken.sol";

/// @title TheDAO
/// @notice Faithful minimal reproduction of The DAO (2016) vulnerable pattern.
///         During the creation phase depositors send ETH via `fund` and receive
///         DAO tokens 1:1. A token holder withdraws their share with `splitDAO`,
///         which sends ETH to the recipient via a low-level `.call` **before**
///         settling (burning) the token balance. This is the real 2016
///         checks-effects-interactions violation: a malicious recipient's
///         `receive()` re-enters `splitDAO` while its balance is still intact,
///         draining ETH repeatedly. The reward-account indirection of the
///         original contract is omitted; the essential flaw (send-before-settle)
///         is preserved exactly.
///
/// @dev The arithmetic mirrors The DAO's Solidity 0.4.6 behaviour (wrapping);
///      `token.burn` uses `unchecked`. The vulnerability is the interaction
///      ordering, not the arithmetic.
contract TheDAO {
    DAOToken public immutable token;

    event Funded(address indexed funder, uint256 ethAmount, uint256 tokensMinted);
    event Split(address indexed splitter, uint256 amount);

    constructor(address token_) {
        token = DAOToken(token_);
    }

    /// @notice Creation phase: send ETH, receive DAO tokens 1:1.
    function fund() external payable {
        require(msg.value > 0, "DAO: zero value");
        token.mint(msg.sender, msg.value);
        emit Funded(msg.sender, msg.value, msg.value);
    }

    /// @notice Withdraw `amount` of your DAO share as ETH. The ETH is sent via
    ///         a low-level `.call` **before** the token balance is settled — the
    ///         real 2016 ordering — so a recipient implementing `receive()` can
    ///         re-enter `splitDAO` and drain ETH while the balance is stale.
    function splitDAO(uint256 amount) external {
        require(token.balanceOf(msg.sender) >= amount, "DAO: insufficient balance");
        // INTERACTION before EFFECTS — the 2016 checks-effects-interactions flaw.
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "DAO: ETH transfer failed");
        // EFFECTS: settle the balance only after the external call.
        token.burn(msg.sender, amount);
        emit Split(msg.sender, amount);
    }

    receive() external payable {}
}
