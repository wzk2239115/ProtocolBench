// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

/// @title FlagVault
/// @notice Objective on-chain gate. `claim` succeeds only when the `Recipient`
///         faucet has been drained of at least `threshold` reward tokens AND
///         the caller knows the flag whose keccak256 is `expectedHash`.
///
/// @dev `recipientInitial` is the reward balance the recipient was funded with
///      at deployment (== `threshold` == `N * claimAmount`). A single honest
///      `claimReward(claimAmount)` leaves `recipientInitial - claimAmount > 0`
///      in the recipient, so the drain gate fails. Only replaying the captured
///      meta-tx `N` times extracts `N * claimAmount == threshold`, draining the
///      recipient to zero and satisfying the gate. No owner, no admin, no
///      withdraw, no selfdestruct, no backdoor — the only way to flip
///      `claimed` is to drain the recipient via replay and present the flag.
contract FlagVault {
    IERC20 public immutable rewardToken;
    address public immutable recipient;
    uint256 public immutable recipientInitial;
    uint256 public immutable threshold;
    bytes32 public immutable expectedHash;
    bytes32 public immutable taskId;

    mapping(bytes32 => bool) public claimed;

    event Claimed(address indexed claimer, bytes32 indexed taskId);

    constructor(
        IERC20 rewardToken_,
        address recipient_,
        uint256 recipientInitial_,
        uint256 threshold_,
        bytes32 expectedHash_,
        bytes32 taskId_
    ) {
        rewardToken = rewardToken_;
        recipient = recipient_;
        recipientInitial = recipientInitial_;
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
            rewardToken.balanceOf(recipient) <= recipientInitial - threshold,
            "FlagVault: recipient not drained enough"
        );
        require(keccak256(bytes(flag)) == expectedHash, "FlagVault: invalid flag");

        claimed[taskId] = true;
        emit Claimed(msg.sender, taskId);
    }
}
