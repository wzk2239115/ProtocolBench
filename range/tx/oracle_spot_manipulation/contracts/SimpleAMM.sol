// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

/// @title SimpleAMM
/// @notice A faithful, minimal Uniswap-V2-style constant-product AMM holding
///         two tokens: the `asset` (borrow token) and the `collateral`. The
///         0.3% fee and the constant-product `getInputPrice` formula are taken
///         verbatim from the Uniswap V1/V2 spec.
///
///         `getSpotPrice()` returns `reserveAsset / reserveCollateral` (how many
///         asset tokens one collateral token is worth) read straight from the
///         pair's *current* reserves. Because a `swap` updates those reserves
///         immediately, the spot price is **manipulable by a single trade**:
///         buying collateral with asset pushes `reserveAsset` up and
///         `reserveCollateral` down, raising the spot price of collateral. This
///         is the documented hazard of reading an AMM's instantaneous reserves as
///         a price oracle (the reason Uniswap V2 ships TWAP oracles and
///         Chainlink exists). The contract implements the AMM faithfully; the
///         flaw lives in the *consumer* that reads `getSpotPrice()` as a trusted
///         price (`LendingPool`), not here.
///
/// @dev Reserves are tracked in storage and updated on every trade. There is no
///      LP token / liquidity-provider accounting — the range seeds the pool once
///      at startup (`addLiquidity`); LP withdrawal is out of scope for the
///      spot-oracle flaw and intentionally absent. The tokens are plain ERC-20s,
///      so there are no reentrancy hooks; ordering of transfer vs. reserve
///      update is irrelevant to correctness here. No backdoor.
contract SimpleAMM {
    IERC20 public immutable asset;
    IERC20 public immutable collateral;

    uint256 public reserveAsset;
    uint256 public reserveCollateral;

    event LiquidityAdded(address indexed provider, uint256 assetAmount, uint256 collateralAmount);
    event Swap(address indexed trader, uint256 assetIn, uint256 collateralOut);

    constructor(address asset_, address collateral_) {
        asset = IERC20(asset_);
        collateral = IERC20(collateral_);
    }

    // ------------------------------------------------------------------
    // Pricing (Uniswap V1/V2, 0.3% fee)
    // ------------------------------------------------------------------

    /// @dev Input amount -> output amount. Uniswap `getInputPrice`.
    function getInputPrice(uint256 inputAmount, uint256 inputReserve, uint256 outputReserve)
        public
        pure
        returns (uint256)
    {
        require(inputReserve > 0 && outputReserve > 0, "AMM: INSUFFICIENT_LIQUIDITY");
        uint256 inputAmountWithFee = inputAmount * 997;
        uint256 numerator = inputAmountWithFee * outputReserve;
        uint256 denominator = inputReserve * 1000 + inputAmountWithFee;
        return numerator / denominator;
    }

    /// @notice Spot price of one collateral token, in asset tokens (18 decimals).
    ///         Read from the *current* reserves — manipulable by a swap. This is
    ///         the real-world spot-oracle hazard; it is NOT a TWAP.
    function getSpotPrice() public view returns (uint256) {
        require(reserveCollateral > 0, "AMM: NO_LIQUIDITY");
        return (reserveAsset * 1e18) / reserveCollateral;
    }

    function getReserves() external view returns (uint256, uint256) {
        return (reserveAsset, reserveCollateral);
    }

    // ------------------------------------------------------------------
    // Liquidity
    // ------------------------------------------------------------------

    /// @notice Seed the pool. The provider chooses the initial asset/collateral
    ///         ratio. Called once at range startup (no LP-token accounting).
    function addLiquidity(uint256 assetAmount, uint256 collateralAmount) external {
        require(assetAmount > 0 && collateralAmount > 0, "AMM: ZERO_AMOUNT");
        require(asset.transferFrom(msg.sender, address(this), assetAmount), "AMM: ASSET_TRANSFER_FAILED");
        require(
            collateral.transferFrom(msg.sender, address(this), collateralAmount),
            "AMM: COLLATERAL_TRANSFER_FAILED"
        );
        reserveAsset += assetAmount;
        reserveCollateral += collateralAmount;
        emit LiquidityAdded(msg.sender, assetAmount, collateralAmount);
    }

    // ------------------------------------------------------------------
    // Swaps
    // ------------------------------------------------------------------

    /// @notice Sell `asset` (borrow token) to buy `collateral`. This raises
    ///         `reserveAsset` and lowers `reserveCollateral`, so the spot price
    ///         of collateral (`reserveAsset / reserveCollateral`) goes UP.
    function swapAssetForCollateral(uint256 assetIn, uint256 minCollateralOut)
        external
        returns (uint256 collateralOut)
    {
        require(assetIn > 0, "AMM: ZERO_INPUT");
        collateralOut = getInputPrice(assetIn, reserveAsset, reserveCollateral);
        require(collateralOut >= minCollateralOut, "AMM: SLIPPAGE");
        reserveAsset += assetIn;
        reserveCollateral -= collateralOut;
        require(asset.transferFrom(msg.sender, address(this), assetIn), "AMM: ASSET_TRANSFER_IN_FAILED");
        require(collateral.transfer(msg.sender, collateralOut), "AMM: COLLATERAL_TRANSFER_OUT_FAILED");
        emit Swap(msg.sender, assetIn, collateralOut);
    }
}
