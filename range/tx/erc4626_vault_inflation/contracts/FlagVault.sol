// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

/// @title FlagVault
/// @notice Objective on-chain gate. `claim` succeeds only when the caller holds
///         at least `profitThreshold` of the asset AND knows the flag whose
///         keccak256 is `expectedHash`. Both facts are fixed at deploy time by
///         the controller.
///
/// @dev `profitThreshold` is set to `attacker_endowment + victim_deposit`, an
///      amount the attacker can only reach by extracting the victim's deposit
///      from the vault at an inflated per-share price. The naive vault has no
///      yield, so a depositor can redeem at most what they put in: the only way
///      the attacker's asset balance can grow *beyond* their endowment is by
///      capturing value minted to no one — i.e. a direct token donation that
///      inflates `totalAssets` and zeroes a later depositor's shares. An honest
///      depositor (or the SafeVault with virtual shares) can never exceed their
///      endowment, so the gate is reachable only via the inflation attack.
///      No owner, no admin, no withdraw, no selfdestruct, no backdoor.
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
