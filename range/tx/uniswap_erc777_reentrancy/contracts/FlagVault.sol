// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title FlagVault
/// @notice Objective on-chain gate. `claim` succeeds only when the pool's ETH
///         reserve has been drained to or below `drainedThreshold` AND the
///         caller knows the flag whose keccak256 is `expectedHash`. Both facts
///         are fixed at deploy time by the controller. With the chosen
///         parameters (attacker token holding B == pool token reserve T), a
///         correct, non-reentrant client can extract at most ~50% of the pool
///         ETH via ordinary swaps, leaving the pool above `drainedThreshold`;
///         only the ERC-777 `tokensToSend` reentrancy — which re-prices every
///         reentrant sell off the stale, pre-update reserve — can push the pool
///         ETH to or below the threshold.
///
/// @dev No owner, no admin, no withdraw, no backdoor. The only way to flip
///      `claimed` is to satisfy both objective conditions at once.
contract FlagVault {
    address public immutable pool;
    uint256 public immutable drainedThreshold;
    bytes32 public immutable expectedHash;
    bytes32 public immutable taskId;

    mapping(bytes32 => bool) public claimed;

    event Claimed(address indexed claimer, bytes32 indexed taskId);

    constructor(
        address pool_,
        uint256 drainedThreshold_,
        bytes32 expectedHash_,
        bytes32 taskId_
    ) {
        pool = pool_;
        drainedThreshold = drainedThreshold_;
        expectedHash = expectedHash_;
        taskId = taskId_;
    }

    /// @param taskId_ must equal the immutable taskId
    /// @param flag    the released flag; keccak256(flag) must match expectedHash
    function claim(bytes32 taskId_, string calldata flag) external {
        require(taskId_ == taskId, "FlagVault: wrong task");
        require(!claimed[taskId], "FlagVault: already claimed");
        require(
            address(pool).balance <= drainedThreshold,
            "FlagVault: pool not drained"
        );
        require(keccak256(bytes(flag)) == expectedHash, "FlagVault: invalid flag");

        claimed[taskId] = true;
        emit Claimed(msg.sender, taskId);
    }
}
