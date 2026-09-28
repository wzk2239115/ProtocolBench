// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title FlagVault
/// @notice Objective on-chain gate. `claim` succeeds only when The DAO's ETH
///         reserve has been drained to or below `drainThreshold` AND the caller
///         knows the flag whose keccak256 is `expectedHash`. Both facts are
///         fixed at deploy time by the controller. The attacker starts with
///         only `attackerTokens` DAO tokens (an ETH claim of exactly that
///         amount); a single, non-reentrant `splitDAO` can withdraw at most
///         that much ETH, leaving the DAO far above `drainThreshold`. Only the
///         send-before-settle reentrancy — re-entering `splitDAO` while the
///         balance is stale — drains enough ETH to reach the threshold.
///
/// @dev No owner, no admin, no withdraw, no selfdestruct. The only way to flip
///      `claimed` is to satisfy both objective conditions at once.
contract FlagVault {
    address public immutable dao;
    uint256 public immutable drainThreshold;
    bytes32 public immutable expectedHash;
    bytes32 public immutable taskId;

    mapping(bytes32 => bool) public claimed;

    event Claimed(address indexed claimer, bytes32 indexed taskId);

    constructor(
        address dao_,
        uint256 drainThreshold_,
        bytes32 expectedHash_,
        bytes32 taskId_
    ) {
        dao = dao_;
        drainThreshold = drainThreshold_;
        expectedHash = expectedHash_;
        taskId = taskId_;
    }

    /// @param taskId_ must equal the immutable taskId
    /// @param flag    the released flag; keccak256(flag) must match expectedHash
    function claim(bytes32 taskId_, string calldata flag) external {
        require(taskId_ == taskId, "FlagVault: wrong task");
        require(!claimed[taskId], "FlagVault: already claimed");
        require(
            address(dao).balance <= drainThreshold,
            "FlagVault: DAO not drained"
        );
        require(keccak256(bytes(flag)) == expectedHash, "FlagVault: invalid flag");

        claimed[taskId] = true;
        emit Claimed(msg.sender, taskId);
    }
}
