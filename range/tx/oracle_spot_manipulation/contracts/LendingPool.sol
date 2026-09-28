// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SimpleAMM} from "./SimpleAMM.sol";

/// @title LendingPool
/// @notice A minimal over-collateralised lending pool. Lenders `supply` the
///         borrow `asset`; borrowers `depositCollateral` collateral tokens and
///         `borrow` asset against it. The collateral's value is priced by the
///         `SimpleAMM`'s `getSpotPrice()` — i.e. the AMM's *instantaneous*
///         reserves, with no TWAP and no deviation/bounds check.
///
///         This faithfully reproduces the real-world 2020 design hazard (bZx /
///         dYdX-class incidents): a lending market that reads a manipulable
///         AMM spot price as if it were a trustworthy oracle. An attacker swaps
///         to move the spot price, then borrows at the inflated collateral
///         value, extracting more asset than the collateral is really worth and
///         leaving the pool undercollateralised. The flaw is the use of the
///         spot price as an oracle — a documented design hazard — NOT an
///         injected bug. The fix is `LendingPoolSafe` (a price-deviation bounds
///         check, the documented mitigation).
///
/// @dev `maxBorrow = collateralAmount * getSpotPrice() * ltvBps / 1e18 / 10000`.
///      Borrowing is bounded by outstanding debt vs. borrowing power (faithful
///      lending-pool accounting). No reentrancy guard is needed: the flaw is
///      the oracle, not reentrancy, and the tokens are plain ERC-20s.
contract LendingPool {
    IERC20 public immutable asset;
    IERC20 public immutable collateral;
    SimpleAMM public immutable amm;
    uint256 public immutable ltvBps; // loan-to-value in basis points (8000 = 80%)

    mapping(address => uint256) public collateralBalance;
    mapping(address => uint256) public borrowedAsset;

    event Supply(address indexed supplier, uint256 assetAmount);
    event DepositCollateral(address indexed depositor, uint256 collateralAmount);
    event Borrow(address indexed borrower, uint256 collateralAmount, uint256 assetBorrowed);

    constructor(address asset_, address collateral_, address amm_, uint256 ltvBps_) {
        asset = IERC20(asset_);
        collateral = IERC20(collateral_);
        amm = SimpleAMM(amm_);
        ltvBps = ltvBps_;
    }

    /// @notice Lenders supply asset tokens the pool can lend out.
    function supply(uint256 assetAmount) external {
        require(assetAmount > 0, "LP: ZERO_AMOUNT");
        require(asset.transferFrom(msg.sender, address(this), assetAmount), "LP: SUPPLY_FAILED");
        emit Supply(msg.sender, assetAmount);
    }

    /// @notice Deposit collateral tokens to back your borrows.
    function depositCollateral(uint256 collateralAmount) external {
        require(collateralAmount > 0, "LP: ZERO_COLLATERAL");
        require(
            collateral.transferFrom(msg.sender, address(this), collateralAmount),
            "LP: COLLATERAL_TRANSFER_FAILED"
        );
        collateralBalance[msg.sender] += collateralAmount;
        emit DepositCollateral(msg.sender, collateralAmount);
    }

    /// @notice Max asset currently borrowable against `collateralAmount`, priced
    ///         by the AMM spot price (the manipulable oracle).
    function maxBorrow(uint256 collateralAmount) public view returns (uint256) {
        uint256 price = amm.getSpotPrice(); // asset per collateral (18 decimals)
        uint256 collateralValueInAsset = (collateralAmount * price) / 1e18;
        return (collateralValueInAsset * ltvBps) / 10000;
    }

    /// @notice Borrow `assetAmount` against your deposited collateral.
    function borrow(uint256 assetAmount) external {
        uint256 col = collateralBalance[msg.sender];
        require(col > 0, "LP: NO_COLLATERAL");
        uint256 max = maxBorrow(col);
        require(borrowedAsset[msg.sender] + assetAmount <= max, "LP: EXCEEDS_BORROWING_POWER");
        require(asset.transfer(msg.sender, assetAmount), "LP: BORROW_FAILED");
        borrowedAsset[msg.sender] += assetAmount;
        emit Borrow(msg.sender, col, assetAmount);
    }
}
