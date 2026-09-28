// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IERC4626} from "@openzeppelin/contracts/interfaces/IERC4626.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";

/// @title NaiveVault
/// @notice A faithful, naive ERC-4626 "Tokenized Vault Standard" implementation
///         using the documented *pre-fix* linear-conversion design:
///
///             shares = assets * totalSupply / totalAssets
///
///         with NO virtual shares and NO dead-shares offset. The first deposit
///         (totalAssets == 0) mints shares 1:1 with assets.
///
/// @dev This is the vulnerable form of the standard. Because `totalAssets()` is
///      `asset.balanceOf(address(this))`, a direct token `transfer` to the vault
///      (a "donation") increases `totalAssets` without minting shares, inflating
///      the per-share price. A first depositor can donate a large amount right
///      after their 1-wei deposit so that every later `previewDeposit` rounds
///      down to 0 shares: later depositors lose their assets to the attacker's
///      single share. OpenZeppelin's own ERC-4626 documentation describes this
///      exact "donation / inflation attack" and ships the `_decimalsOffset()` /
///      virtual-shares mitigation (see `SafeVault.sol`); this contract
///      deliberately omits that mitigation, faithfully reproducing the
///      real-world pre-fix design. No injected bug, no backdoor.
contract NaiveVault is ERC20, IERC4626 {
    using SafeERC20 for IERC20;
    using Math for uint256;

    IERC20 private immutable _asset;

    constructor(address asset_) ERC20("Naive Vault Share", "nVLT") {
        _asset = IERC20(asset_);
    }

    // ---- IERC4626 views ------------------------------------------------
    function asset() public view returns (address) {
        return address(_asset);
    }

    function totalAssets() public view returns (uint256) {
        return _asset.balanceOf(address(this));
    }

    function convertToShares(uint256 assets) public view returns (uint256) {
        return _convertToShares(assets, Math.Rounding.Floor);
    }

    function convertToAssets(uint256 shares) public view returns (uint256) {
        return _convertToAssets(shares, Math.Rounding.Floor);
    }

    function maxDeposit(address) public pure returns (uint256) {
        return type(uint256).max;
    }

    function maxMint(address) public pure returns (uint256) {
        return type(uint256).max;
    }

    function maxWithdraw(address owner) public view returns (uint256) {
        return _convertToAssets(balanceOf(owner), Math.Rounding.Floor);
    }

    function maxRedeem(address owner) public view returns (uint256) {
        return balanceOf(owner);
    }

    function previewDeposit(uint256 assets) public view returns (uint256) {
        return _convertToShares(assets, Math.Rounding.Floor);
    }

    function previewMint(uint256 shares) public view returns (uint256) {
        return _convertToAssets(shares, Math.Rounding.Ceil);
    }

    function previewWithdraw(uint256 assets) public view returns (uint256) {
        return _convertToShares(assets, Math.Rounding.Ceil);
    }

    function previewRedeem(uint256 shares) public view returns (uint256) {
        return _convertToAssets(shares, Math.Rounding.Floor);
    }

    // ---- NAIVE linear conversion (NO virtual shares / offset) ----------
    /// @dev `shares = assets * totalSupply / totalAssets`, first deposit 1:1.
    ///      This is the real-world pre-fix form; it is vulnerable to donation
    ///      inflation because `totalAssets` can be raised without minting.
    function _convertToShares(uint256 assets, Math.Rounding rounding) internal view returns (uint256) {
        uint256 supply = totalSupply();
        uint256 _totalAssets = totalAssets();
        if (supply == 0 || _totalAssets == 0) {
            return assets; // first deposit: shares 1:1 with assets
        }
        return assets.mulDiv(supply, _totalAssets, rounding);
    }

    function _convertToAssets(uint256 shares, Math.Rounding rounding) internal view returns (uint256) {
        uint256 supply = totalSupply();
        if (supply == 0) {
            return 0;
        }
        return shares.mulDiv(totalAssets(), supply, rounding);
    }

    // ---- IERC4626 mutations -------------------------------------------
    function deposit(uint256 assets, address receiver) public returns (uint256 shares) {
        shares = previewDeposit(assets);
        _deposit(_msgSender(), receiver, assets, shares);
    }

    function mint(uint256 shares, address receiver) public returns (uint256 assets) {
        assets = previewMint(shares);
        _deposit(_msgSender(), receiver, assets, shares);
    }

    function withdraw(uint256 assets, address receiver, address owner) public returns (uint256 shares) {
        shares = previewWithdraw(assets);
        _withdraw(_msgSender(), receiver, owner, assets, shares);
    }

    function redeem(uint256 shares, address receiver, address owner) public returns (uint256 assets) {
        assets = previewRedeem(shares);
        _withdraw(_msgSender(), receiver, owner, assets, shares);
    }

    function _deposit(address caller, address receiver, uint256 assets, uint256 shares) internal {
        // Slither-disable: transfer-before-mint is fine — assets and shares are
        // settled atomically; reentrancy would re-enter before minting with no
        // shares to redeem, a no-op. (Matches OZ's ordering rationale.)
        _asset.safeTransferFrom(caller, address(this), assets);
        _mint(receiver, shares);
        emit Deposit(caller, receiver, assets, shares);
    }

    function _withdraw(address caller, address receiver, address owner, uint256 assets, uint256 shares) internal {
        if (caller != owner) {
            _spendAllowance(owner, caller, shares);
        }
        _burn(owner, shares);
        _asset.safeTransfer(receiver, assets);
        emit Withdraw(caller, receiver, owner, assets, shares);
    }
}
