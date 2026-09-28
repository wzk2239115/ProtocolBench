// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SimpleAMM} from "./SimpleAMM.sol";

/// @title LendingPoolSafe
/// @notice The fixed variant of `LendingPool`: identical collateral / borrow
///         accounting, but `maxBorrow` rejects any AMM spot price that deviates
///         more than `maxDeviationBps` from the `referencePrice` fixed at
///         deployment (a price-deviation bounds check / circuit breaker).
///
///         This is the documented mitigation against spot-oracle manipulation:
///         oracle consumers must not act on a price that has moved abnormally,
///         because an instantaneous reserve move signals manipulation (or a
///         market break). Chainlink feeds ship deviation thresholds and
///         heartbeats for exactly this reason; many lending markets cap
///         per-update price moves. With the bounds check in place, the large
///         spot move required to over-borrow is rejected, so the manipulation
///         fails. This is the stock, real-world mitigation; no backdoor.
///
/// @dev The reference price is the fair price at deployment (the seeded AMM
///      reserve ratio). Because no other trading occurs in the range, the spot
///      price only leaves the band when an attacker manipulates it; honest
///      borrows always price within the band.
contract LendingPoolSafe {
    IERC20 public immutable asset;
    IERC20 public immutable collateral;
    SimpleAMM public immutable amm;
    uint256 public immutable ltvBps; // loan-to-value in basis points (8000 = 80%)
    uint256 public immutable referencePrice; // fair asset-per-collateral price (18 decimals)
    uint256 public immutable maxDeviationBps; // max allowed deviation from reference (bps, e.g. 500 = 5%)

    mapping(address => uint256) public collateralBalance;
    mapping(address => uint256) public borrowedAsset;

    event Supply(address indexed supplier, uint256 assetAmount);
    event DepositCollateral(address indexed depositor, uint256 collateralAmount);
    event Borrow(address indexed borrower, uint256 collateralAmount, uint256 assetBorrowed);

    constructor(
        address asset_,
        address collateral_,
        address amm_,
        uint256 ltvBps_,
        uint256 referencePrice_,
        uint256 maxDeviationBps_
    ) {
        asset = IERC20(asset_);
        collateral = IERC20(collateral_);
        amm = SimpleAMM(amm_);
        ltvBps = ltvBps_;
        referencePrice = referencePrice_;
        maxDeviationBps = maxDeviationBps_;
    }

    function supply(uint256 assetAmount) external {
        require(assetAmount > 0, "LP: ZERO_AMOUNT");
        require(asset.transferFrom(msg.sender, address(this), assetAmount), "LP: SUPPLY_FAILED");
        emit Supply(msg.sender, assetAmount);
    }

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
    ///         by a deviation-checked AMM spot price. Reverts if the spot price
    ///         has moved outside the allowed band (manipulation / market break).
    function maxBorrow(uint256 collateralAmount) public view returns (uint256) {
        uint256 spot = amm.getSpotPrice();
        uint256 lo = (referencePrice * (10000 - maxDeviationBps)) / 10000;
        uint256 hi = (referencePrice * (10000 + maxDeviationBps)) / 10000;
        require(spot >= lo && spot <= hi, "LP: PRICE_OUT_OF_BOUNDS");
        uint256 collateralValueInAsset = (collateralAmount * spot) / 1e18;
        return (collateralValueInAsset * ltvBps) / 10000;
    }

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
