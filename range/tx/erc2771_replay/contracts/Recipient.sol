// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {ERC2771Context} from "@openzeppelin/contracts/metatx/ERC2771Context.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

/// @title Recipient
/// @notice An ERC-2771 meta-transaction recipient. It extends OpenZeppelin's
///         `ERC2771Context` (v5.1.0) so that `_msgSender()` recovers the original
///         signer from the 20-byte calldata suffix appended by a trusted
///         `TrustedForwarder`. The protected function `claimReward(amount)` pays
///         `amount` of the reward token to `_msgSender()` (the meta-tx signer).
///
/// @dev `claimReward` is ONLY reachable through the trusted forwarder: a direct
///      call has `msg.sender != trustedForwarder`, so the guard reverts and
///      `_msgSender()` is never the raw caller. This is the standard ERC-2771
///      recipient pattern; no injected bug, no backdoor. The replay hazard lives
///      in the forwarder, not here.
contract Recipient is ERC2771Context {
    IERC20 public immutable rewardToken;

    event RewardClaimed(address indexed claimer, uint256 amount);

    constructor(address trustedForwarder, IERC20 rewardToken_)
        ERC2771Context(trustedForwarder)
    {
        rewardToken = rewardToken_;
    }

    /// @notice Pay `amount` reward tokens to the meta-tx signer (`_msgSender()`).
    ///         Only the trusted forwarder may invoke this; direct calls revert.
    function claimReward(uint256 amount) external {
        require(isTrustedForwarder(msg.sender), "Recipient: only trusted forwarder");
        address claimer = _msgSender();
        require(rewardToken.transfer(claimer, amount), "Recipient: transfer failed");
        emit RewardClaimed(claimer, amount);
    }
}
