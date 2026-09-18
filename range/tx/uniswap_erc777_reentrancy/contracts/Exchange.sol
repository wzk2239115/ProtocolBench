// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

/// @title Exchange
/// @notice A faithful Uniswap-V1-style ETH/token exchange. It holds ETH and an
///         ERC-20-compatible token, prices every swap off its *current* token
///         balance (`token.balanceOf(address(this))`) and ETH balance
///         (`address(this).balance`), and — exactly as the real 2020 code —
///         carries **no reentrancy guard**. The swap functions follow the
///         real Uniswap V1 ordering (price first, then the external token
///         transfer, then the ETH transfer), which is reentrancy-unsafe when
///         the token is an ERC-777.
///
/// @dev The constant-product math (0.3% fee) is taken verbatim from the
///      Uniswap V1 spec. `addLiquidity` is a faithful minimal seeder (the range
///      only ever performs the initial deposit); LP-token withdrawal is out of
///      scope for the swap-reentrancy flaw and intentionally absent.
contract Exchange {
    IERC20 public immutable token;

    uint256 public totalLiquidity;

    event AddLiquidity(address indexed provider, uint256 ethAmount, uint256 tokenAmount);
    event EthToTokenSwap(address indexed buyer, uint256 ethSold, uint256 tokensBought);
    event TokenToEthSwap(address indexed seller, uint256 tokensSold, uint256 ethBought);

    constructor(address token_) {
        token = IERC20(token_);
    }

    // ------------------------------------------------------------------
    // Pricing (Uniswap V1, 0.3% fee)
    // ------------------------------------------------------------------

    /// @dev Input amount -> output amount. Uniswap V1 `getInputPrice`.
    function getInputPrice(uint256 inputAmount, uint256 inputReserve, uint256 outputReserve)
        public
        pure
        returns (uint256)
    {
        require(inputReserve > 0 && outputReserve > 0, "EXCHANGE: INSUFFICIENT_LIQUIDITY");
        uint256 inputAmountWithFee = inputAmount * 997;
        uint256 numerator = inputAmountWithFee * outputReserve;
        uint256 denominator = inputReserve * 1000 + inputAmountWithFee;
        return numerator / denominator;
    }

    /// @dev Output amount -> input amount. Uniswap V1 `getOutputPrice`.
    function getOutputPrice(uint256 outputAmount, uint256 inputReserve, uint256 outputReserve)
        public
        pure
        returns (uint256)
    {
        require(inputReserve > 0 && outputReserve > 0, "EXCHANGE: INSUFFICIENT_LIQUIDITY");
        require(outputAmount < outputReserve, "EXCHANGE: INSUFFICIENT_LIQUIDITY");
        uint256 outputAmountWithFee = outputAmount * 1000;
        uint256 numerator = outputAmountWithFee * inputReserve;
        uint256 denominator = (outputReserve - outputAmount) * 997;
        return (numerator / denominator) + 1;
    }

    function getEthToTokenInputPrice(uint256 ethSold) public view returns (uint256) {
        require(ethSold > 0, "EXCHANGE: ZERO_INPUT");
        uint256 tokenReserve = token.balanceOf(address(this));
        uint256 ethReserve = address(this).balance;
        return getInputPrice(ethSold, ethReserve, tokenReserve);
    }

    function getTokenToEthInputPrice(uint256 tokensSold) public view returns (uint256) {
        require(tokensSold > 0, "EXCHANGE: ZERO_INPUT");
        uint256 tokenReserve = token.balanceOf(address(this));
        uint256 ethReserve = address(this).balance;
        return getInputPrice(tokensSold, tokenReserve, ethReserve);
    }

    // ------------------------------------------------------------------
    // Liquidity
    // ------------------------------------------------------------------

    /// @notice Seed the pool. On the first deposit the provider chooses the
    ///         initial ETH/token ratio (`msg.value` ETH + `maxTokens` tokens).
    ///         Subsequent deposits are proportional (Uniswap V1 rule).
    function addLiquidity(uint256 maxTokens, uint256 deadline)
        external
        payable
        returns (uint256)
    {
        require(deadline >= block.timestamp, "EXCHANGE: DEADLINE");
        require(msg.value > 0 && maxTokens > 0, "EXCHANGE: ZERO_AMOUNT");

        uint256 ethReserve = address(this).balance - msg.value;
        uint256 tokenReserve = token.balanceOf(address(this));
        uint256 liquidity;

        if (totalLiquidity == 0) {
            liquidity = msg.value;
            require(
                token.transferFrom(msg.sender, address(this), maxTokens),
                "EXCHANGE: TRANSFER_IN_FAILED"
            );
        } else {
            require(ethReserve > 0, "EXCHANGE: INSUFFICIENT_LIQUIDITY");
            uint256 tokenAmount = (msg.value * tokenReserve) / ethReserve;
            require(tokenAmount <= maxTokens, "EXCHANGE: SLIPPAGE");
            require(
                token.transferFrom(msg.sender, address(this), tokenAmount),
                "EXCHANGE: TRANSFER_IN_FAILED"
            );
            liquidity = (msg.value * totalLiquidity) / ethReserve;
        }

        totalLiquidity += liquidity;
        emit AddLiquidity(msg.sender, msg.value, maxTokens);
        return liquidity;
    }

    // ------------------------------------------------------------------
    // Swaps (no reentrancy guard — the real 2020 flaw)
    // ------------------------------------------------------------------

    /// @notice Buy tokens with ETH. Uniswap V1 `ethToTokenSwapInput` ordering:
    ///         price from current balances, then token.transfer out.
    function ethToTokenSwapInput(uint256 minTokens, uint256 deadline)
        external
        payable
        returns (uint256 tokensBought)
    {
        require(deadline >= block.timestamp && msg.value > 0, "EXCHANGE: INVALID_CALL");
        uint256 tokenReserve = token.balanceOf(address(this));
        uint256 ethReserve = address(this).balance - msg.value;
        tokensBought = getInputPrice(msg.value, ethReserve, tokenReserve);
        require(tokensBought >= minTokens, "EXCHANGE: SLIPPAGE");
        require(token.transfer(msg.sender, tokensBought), "EXCHANGE: TRANSFER_OUT_FAILED");
        emit EthToTokenSwap(msg.sender, msg.value, tokensBought);
    }

    /// @notice Sell tokens for ETH. Uniswap V1 `tokenToEthSwapInput` ordering:
    ///         price from current balances (getInputPrice), then
    ///         token.transferFrom in, then `msg.sender.transfer` out. The
    ///         external `transferFrom` triggers an ERC-777 `tokensToSend` hook
    ///         on the sender _before_ the token balance is updated, so a
    ///         reentrant call observes stale reserves.
    function tokenToEthSwapInput(uint256 tokensSold, uint256 minEth, uint256 deadline)
        external
        returns (uint256 ethBought)
    {
        require(deadline >= block.timestamp && tokensSold > 0, "EXCHANGE: INVALID_CALL");
        uint256 tokenReserve = token.balanceOf(address(this));
        uint256 ethReserve = address(this).balance;
        ethBought = getInputPrice(tokensSold, tokenReserve, ethReserve);
        require(ethBought >= minEth, "EXCHANGE: SLIPPAGE");
        require(
            token.transferFrom(msg.sender, address(this), tokensSold),
            "EXCHANGE: TRANSFER_IN_FAILED"
        );
        payable(msg.sender).transfer(ethBought);
        emit TokenToEthSwap(msg.sender, tokensSold, ethBought);
    }

    receive() external payable {}
}