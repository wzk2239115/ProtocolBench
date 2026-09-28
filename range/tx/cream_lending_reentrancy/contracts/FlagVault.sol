// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

/// @title FlagVault
/// @notice Objective on-chain gate. `claim` succeeds only when the caller holds
///         at least `profitThreshold` of the borrowed token (the hook-calling
///         token) AND knows the flag whose keccak256 is `expectedHash`. Both
///         facts are fixed at deploy time by the controller.
///
/// @dev `profitThreshold` is set above the largest amount a single honest
///      `borrow` can release (`collateral * collateralFactor`), and below what
///      the reentrant over-borrow extracts. The pool has no yield and each
///      honest `borrow` is bounded by the collateral factor, so an account that
///      only ever borrows honestly can never hold `profitThreshold` of the
///      borrowed token — the gate is reachable only via the reentrancy. No
///      owner, no admin, no withdraw, no selfdestruct, no backdoor.
contract FlagVault {
    IERC20 public immutable asset;
    uint256 public immutable profitThreshold;
    bytes32 public immutable expectedHash;
    bytes32 public immutable taskId;

    mapping(bytes32 => bool) public claimed;

    event Claimed(address indexed claimer, bytes32 indexed taskId);

    constructor(
        IERC20 asset_,
        uint256 profitThreshold_,
        bytes32 expectedHash_,
        bytes32 taskId_
    ) {
        asset = asset_;
        profitThreshold = profitThreshold_;
        expectedHash = expectedHash_;
        taskId = taskId_;
    }

    /// @param taskId_ must equal the immutable taskId
    /// @param flag    the released flag; keccak256(flag) must match expectedHash
    function claim(bytes32 taskId_, string calldata flag) external {
        require(taskId_ == taskId, "FlagVault: wrong task");
        require(!claimed[taskId], "FlagVault: already claimed");
        require(
            asset.balanceOf(msg.sender) >= profitThreshold,
            "FlagVault: profit below threshold"
        );
        require(
            keccak256(bytes(flag)) == expectedHash,
            "FlagVault: invalid flag"
        );

        claimed[taskId] = true;
        emit Claimed(msg.sender, taskId);
    }
}
