// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

/// @title FlagVault
/// @notice Objective on-chain gate. `claim` succeeds only when the caller's
///         COMBINED balance across two token deployments reaches `threshold`
///         AND the caller knows the flag whose keccak256 is `expectedHash`.
///
/// @dev `threshold` is set to `2 * permit_value`. A single legitimate `permit`
///      grants `permit_value` on one deployment only; the attacker must obtain
///      `permit_value` on BOTH deployments to reach `2 * permit_value`. The
///      victim signs only one permit (for the source deployment), so the only
///      way to obtain an allowance on the target deployment is to use the
///      captured signature there as well — which succeeds only when the
///      token's domain separator is not bound to the contract address (the
///      naive token). No owner, no admin, no withdraw, no selfdestruct, no
///      backdoor.
contract FlagVault {
    IERC20 public immutable tokenA;
    IERC20 public immutable tokenB;
    uint256 public immutable threshold;
    bytes32 public immutable expectedHash;
    bytes32 public immutable taskId;

    mapping(bytes32 => bool) public claimed;

    event Claimed(address indexed claimer, bytes32 indexed taskId);

    constructor(
        IERC20 tokenA_,
        IERC20 tokenB_,
        uint256 threshold_,
        bytes32 expectedHash_,
        bytes32 taskId_
    ) {
        tokenA = tokenA_;
        tokenB = tokenB_;
        threshold = threshold_;
        expectedHash = expectedHash_;
        taskId = taskId_;
    }

    /// @param taskId_ must equal the immutable taskId
    /// @param flag    the released flag; keccak256(flag) must match expectedHash
    function claim(bytes32 taskId_, string calldata flag) external {
        require(taskId_ == taskId, "FlagVault: wrong task");
        require(!claimed[taskId], "FlagVault: already claimed");
        require(
            tokenA.balanceOf(msg.sender) + tokenB.balanceOf(msg.sender) >= threshold,
            "FlagVault: holding below threshold"
        );
        require(keccak256(bytes(flag)) == expectedHash, "FlagVault: invalid flag");

        claimed[taskId] = true;
        emit Claimed(msg.sender, taskId);
    }
}
