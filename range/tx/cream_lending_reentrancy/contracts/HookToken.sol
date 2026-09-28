// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

/// @title ITokenReceiver
/// @notice The recipient-side callback of a hook-calling token. Mirrors the
///         EIP-777 `ERC777TokensRecipient.tokensReceived` hook, which the
///         standard fires on the recipient *after* the token state is updated.
interface ITokenReceiver {
    /// @dev Called on `to` (or its registered implementer) after the balances
    ///      are updated, so the hook observes the new token state but any
    ///      *external* accounting that has not yet been settled is still stale.
    function tokensReceived(
        address operator,
        address from,
        address to,
        uint256 amount
    ) external;
}

/// @title HookToken
/// @notice A faithful hook-calling ERC-20. It implements the full EIP-20
///         interface on top of the unmodified OpenZeppelin `ERC20` (v5.1.0) and
///         adds exactly one property that EIP-777 mandates and EIP-20 does not:
///         on every transfer, **after** the balances are updated, it calls
///         `ITokenReceiver(to).tokensReceived(...)` on the recipient — the
///         EIP-777 recipient-side hook.
///
/// @dev This is the recipient hook that the real Cream-class hazard composes
///      badly with: a lending pool that pays out the borrowed token *before*
///      settling its own `borrows` accounting gets re-entered from this hook
///      while its state is inconsistent. The hook is **opt-in**: only
///      recipients that explicitly register an implementer via
///      `registerReceiver` receive the callback, so ordinary EOAs and
///      unregistered contracts (the pool itself, the LP, …) transfer tokens
///      without any callback. This is a faithful minimal model of the
///      EIP-777 `ERC777TokensRecipient` hook as discovered through the ERC-1820
///      registry (a recipient only gets the hook if it opted in by registering
///      an implementer). No balance, no allowance, no transfer semantics are
///      altered; the standard EIP-20 behaviour is preserved exactly.
contract HookToken is ERC20 {
    /// @dev opt-in recipient-hook registry: `implementer[account]` is the
    ///      address whose `tokensReceived` is called when `account` receives
    ///      tokens. Zero means "no hook" (the EIP-20 default).
    mapping(address => address) private _receiverImpl;

    constructor(
        string memory name_,
        string memory symbol_,
        uint256 initialSupply
    ) ERC20(name_, symbol_) {
        _mint(msg.sender, initialSupply);
    }

    /// @notice Register `impl` (or `msg.sender`) as the recipient-hook
    ///         implementer for `msg.sender`. An account is its own manager, so
    ///         it may always set its own implementer — mirroring the ERC-1820
    ///         rule that an account can set its own interface implementer.
    function registerReceiver(address impl) external {
        _receiverImpl[msg.sender] = impl;
    }

    /// @dev EIP-20 transfer semantics are unchanged. The ONLY addition is the
    ///      recipient hook fired *after* `super._update` has settled balances
    ///      and emitted `Transfer` — exactly where EIP-777 fires
    ///      `tokensReceived` (OZ ERC777._send: `_callTokensReceived` runs after
    ///      `_move`). Because the hook fires after the token state is updated
    ///      but *before* the pool that called `transfer` returns, any lending
    ///      pool that has not yet settled its own accounting is re-enterable
    ///      from here.
    function _update(address from, address to, uint256 value) internal override {
        super._update(from, to, value);
        address impl = _receiverImpl[to];
        if (impl != address(0)) {
            ITokenReceiver(impl).tokensReceived(_msgSender(), from, to, value);
        }
    }
}
