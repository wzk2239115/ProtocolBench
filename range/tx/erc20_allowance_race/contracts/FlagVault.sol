// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

/// @title FlagVault
/// @notice Objective on-chain gate. `claim` succeeds only when the caller
///         holds at least `threshold` tokens AND knows the flag whose
///         keccak256 is `expectedHash`. Both facts are fixed at deploy time
///         by the controller. The threshold is N + M, an amount that can only
///         be accumulated by exploiting the EIP-20 approve/transferFrom
///         allowance race: the spender collects the OLD allowance N before
///         the owner's second `approve` settles, then collects the NEW
///         allowance M. A correct (race-free) client can never exceed M.
///
/// @dev No owner, no admin, no withdraw, no backdoor. The only way to flip
///      `claimed` is to satisfy both objective conditions at once.
contract FlagVault {
    IERC20 public immutable token;
    uint256 public immutable threshold;
    bytes32 public immutable expectedHash;
    bytes32 public immutable taskId;

    mapping(bytes32 => bool) public claimed;

    event Claimed(address indexed claimer, bytes32 indexed taskId);

    constructor(
        IERC20 token_,
        uint256 threshold_,
        bytes32 expectedHash_,
        bytes32 taskId_
    ) {
        token = token_;
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
            token.balanceOf(msg.sender) >= threshold,
            "FlagVault: holding below threshold"
        );
        require(
            keccak256(bytes(flag)) == expectedHash,
            "FlagVault: invalid flag"
        );

        claimed[taskId] = true;
        emit Claimed(msg.sender, taskId);
    }
}
