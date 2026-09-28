// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {ERC4626} from "@openzeppelin/contracts/token/ERC20/extensions/ERC4626.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

/// @title SafeVault
/// @notice The fixed ERC-4626 variant: OpenZeppelin's `ERC4626` (v5.1.0) with a
///         non-zero `_decimalsOffset()`. This is the official, documented
///         mitigation against the donation / first-depositor inflation attack.
///
/// @dev OZ's `ERC4626` adds *virtual shares* (`totalSupply() + 10**offset`) and
///      *virtual assets / dead shares* (`totalAssets() + 1`) to the conversion:
///
///           shares = assets * (totalSupply + 10**offset) / (totalAssets + 1)
///
///      The virtual shares capture the value of any donation, so an attacker who
///      donates to inflate the price cannot recover the donated amount: the
///      attack becomes unprofitable. With `offset = 18` the virtual shares are
///      `1e18`, so driving a victim's deposit to 0 shares would require a
///      donation astronomically larger than any extractable profit — the
///      inflation fails. See OpenZeppelin's ERC-4626 guide
///      (xref:ROOT:erc4626.adoc#inflation-attack[Inflation Attack]) for the
///      full analysis. No backdoor; this is the stock mitigation.
contract SafeVault is ERC4626 {
    constructor(IERC20 asset_) ERC20("Safe Vault Share", "sVLT") ERC4626(asset_) {}

    /// @dev Strong virtual-shares offset (1e18 virtual shares). The default 0 is
    ///      already "non-profitable" per OZ's analysis; 1e18 makes the donation
    ///      attack orders of magnitude more expensive than any profit, so the
    ///      victim always receives a fair, non-zero amount of shares.
    function _decimalsOffset() internal pure override returns (uint8) {
        return 18;
    }
}
