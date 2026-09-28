// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

/// @title LendingPool
/// @notice A faithful Cream/Compound-style single-pair lending market. Users
///         supply a collateral token (`AssetToken`, a plain ERC-20) and may
///         borrow the borrowable token (`HookToken`, a hook-calling ERC-20) up
///         to a collateral factor:
///
///             maxBorrow = collateral[user] * collateralFactorMantissa / 1e18
///
///         The `borrow` path follows the **real pre-fix Cream ordering**: it
///         transfers the borrowed tokens to `msg.sender` *before* updating
///         `borrows[msg.sender]`, and carries **no reentrancy guard**. Because
///         the borrowable token is a hook-calling token, the payout transfer
///         fires `tokensReceived` on the borrower while the pool's `borrows`
///         accounting is still the pre-borrow value — so a malicious borrower's
///         hook re-enters `borrow` and passes the collateral check against the
///         stale `borrows`, over-borrowing against the same collateral. This is
///         the real Cream (Oct 2021) design hazard: a lending pool composed with
///         a hook-calling token and no reentrancy guard. No injected bug.
///
/// @dev `collateralFactorMantissa` is in 1e18 scale (e.g. 0.75e18 == 75%),
///      matching Compound's mantissa convention. Liquidity of the borrowable
///      token is simply the pool's `borrowToken.balanceOf(address(this))`; the
///      lender side is intentionally minimal (the range focuses on the borrow
///      reentrancy, not cToken accounting).
contract LendingPool {
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

    /// @notice Deposit `amount` of the collateral token; credited 1:1.
    function supplyCollateral(uint256 amount) external {
        require(amount > 0, "POOL: ZERO_AMOUNT");
        collateral[msg.sender] += amount;
        require(
            collateralToken.transferFrom(msg.sender, address(this), amount),
            "POOL: COLLATERAL_IN_FAILED"
        );
        emit SupplyCollateral(msg.sender, amount);
    }

    /// @notice Borrow `amount` of the borrowable token against posted collateral.
    /// @dev    VULNERABLE (real flaw): the payout `borrowToken.transfer`
    ///         happens BEFORE `borrows[msg.sender]` is increased and there is
    ///         no reentrancy guard. The hook-calling borrow token fires
    ///         `tokensReceived` on `msg.sender` during that transfer, so a
    ///         malicious borrower re-enters `borrow` while `borrows[msg.sender]`
    ///         is still the pre-borrow value and passes the collateral check a
    ///         second (third, …) time against the same collateral.
    function borrow(uint256 amount) external {
        require(amount > 0, "POOL: ZERO_AMOUNT");
        uint256 max = (collateral[msg.sender] * collateralFactorMantissa) / 1e18;
        require(borrows[msg.sender] + amount <= max, "POOL: INSUFFICIENT_COLLATERAL");

        // Interaction BEFORE effect — the borrowed token is paid out while the
        // debt ledger is still stale. This is the Cream-class ordering hazard.
        require(borrowToken.transfer(msg.sender, amount), "POOL: BORROW_OUT_FAILED");

        borrows[msg.sender] += amount; // settled too late
        emit Borrow(msg.sender, amount);
    }

    /// @notice Borrowable-token liquidity currently available in the pool.
    function liquidity() external view returns (uint256) {
        return borrowToken.balanceOf(address(this));
    }
}
