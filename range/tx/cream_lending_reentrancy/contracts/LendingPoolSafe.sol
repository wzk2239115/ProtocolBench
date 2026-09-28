// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

/// @title LendingPoolSafe
/// @notice The fixed variant of {LendingPool}: identical collateral/borrow
///         accounting and pricing, but `borrow` applies the two standard
///         mitigations for the Cream-class hook-token reentrancy:
///           1. OpenZeppelin `ReentrancyGuard` (`nonReentrant`) — the
///              reentrant `borrow` from the `tokensReceived` hook reverts.
///           2. Checks-Effects-Interactions — `borrows[msg.sender]` is
///              increased *before* the external payout, so even without the
///              guard the reentrant call would see the updated debt and fail
///              the collateral check.
///         This is the documented fix; used by the negative test. No backdoor.
contract LendingPoolSafe is ReentrancyGuard {
    IERC20 public immutable collateralToken;
    IERC20 public immutable borrowToken;
    uint256 public immutable collateralFactorMantissa;

    mapping(address => uint256) public collateral;
    mapping(address => uint256) public borrows;

    event SupplyCollateral(address indexed supplier, uint256 amount);
    event Borrow(address indexed borrower, uint256 amount);

    constructor(
        address collateralToken_,
        address borrowToken_,
        uint256 collateralFactorMantissa_
    ) {
        collateralToken = IERC20(collateralToken_);
        borrowToken = IERC20(borrowToken_);
        collateralFactorMantissa = collateralFactorMantissa_;
    }

    function supplyCollateral(uint256 amount) external {
        require(amount > 0, "POOL: ZERO_AMOUNT");
        collateral[msg.sender] += amount;
        require(
            collateralToken.transferFrom(msg.sender, address(this), amount),
            "POOL: COLLATERAL_IN_FAILED"
        );
        emit SupplyCollateral(msg.sender, amount);
    }

    /// @dev CEI + nonReentrant: the debt ledger is settled before the external
    ///      payout, and a reentrant call is rejected outright.
    function borrow(uint256 amount) external nonReentrant {
        require(amount > 0, "POOL: ZERO_AMOUNT");
        uint256 max = (collateral[msg.sender] * collateralFactorMantissa) / 1e18;
        require(borrows[msg.sender] + amount <= max, "POOL: INSUFFICIENT_COLLATERAL");

        borrows[msg.sender] += amount; // effect first

        require(borrowToken.transfer(msg.sender, amount), "POOL: BORROW_OUT_FAILED"); // interaction last

        emit Borrow(msg.sender, amount);
    }

    function liquidity() external view returns (uint256) {
        return borrowToken.balanceOf(address(this));
    }
}
