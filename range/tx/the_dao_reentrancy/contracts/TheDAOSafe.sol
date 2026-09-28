// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {DAOToken} from "./DAOToken.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

/// @title TheDAOSafe
/// @notice The fixed variant of {TheDAO}: identical funding and withdrawal
///         semantics but `splitDAO` applies checks-effects-interactions (burn
///         the balance **before** the external call) and is guarded by
///         OpenZeppelin `ReentrancyGuard`. This is the standard mitigation for
///         the 2016 reentrancy and is used by the negative test: the same
///         reentrant exploit reverts here.
contract TheDAOSafe is ReentrancyGuard {
    DAOToken public immutable token;

    event Funded(address indexed funder, uint256 ethAmount, uint256 tokensMinted);
    event Split(address indexed splitter, uint256 amount);

    constructor(address token_) {
        token = DAOToken(token_);
    }

    function fund() external payable {
        require(msg.value > 0, "DAO: zero value");
        token.mint(msg.sender, msg.value);
        emit Funded(msg.sender, msg.value, msg.value);
    }

    function splitDAO(uint256 amount) external nonReentrant {
        require(token.balanceOf(msg.sender) >= amount, "DAO: insufficient balance");
        // EFFECTS before INTERACTION (checks-effects-interactions).
        token.burn(msg.sender, amount);
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "DAO: ETH transfer failed");
        emit Split(msg.sender, amount);
    }

    receive() external payable {}
}
