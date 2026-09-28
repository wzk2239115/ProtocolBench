// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

/// @title FlagVault
/// @notice Objective on-chain gate. `claim` succeeds only when the caller holds
///         at least `profitThreshold` of the borrow asset AND knows the flag
///         whose keccak256 is `expectedHash`. Both facts are fixed at deploy
///         time by the controller.
///
/// @dev `profitThreshold` is set to `attacker_endowment + min_profit`, an amount
///      the attacker can only reach by over-borrowing asset against collateral
///      priced at a manipulated (inflated) AMM spot price. The lending pool
///      generates no yield and borrows are bounded by the collateral value at
///      the *honest* price, so an honest borrower can never end up with more
///      asset than they started with — the only way the attacker's asset
///      balance can grow *beyond* their endowment is to borrow against an
///      inflated collateral value, i.e. to manipulate the spot oracle. An
///      honest borrower (or a bounds-checked pool that rejects the manipulated
///      price) can never reach the threshold, so the gate is reachable only via
///      spot-oracle manipulation. No owner, no admin, no withdraw, no
///      selfdestruct, no backdoor.
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
