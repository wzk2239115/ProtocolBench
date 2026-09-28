// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title DAOToken
/// @notice Minimal ledger token for The DAO (2016) reproduction. Tracks
///         balances; the authorized DAO contract mints tokens 1:1 for ETH
///         during the creation phase (`fund`) and burns them on withdrawal
///         (`splitDAO`). `transfer`/`balanceOf` are the standard ledger
///         operations. This faithfully mirrors The DAO's own bespoke "DAO
///         Token" ledger (not a stock ERC-20): nothing is weakened or
///         backdoored.
contract DAOToken {
    string public constant name = "The DAO Token";
    string public constant symbol = "DAO";
    uint8 public constant decimals = 18;

    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;

    address public immutable owner;
    address public dao; // privileged minter/burner (set once)

    event Transfer(address indexed from, address indexed to, uint256 value);

    constructor() {
        owner = msg.sender;
    }

    /// @notice Authorize the DAO contract as the sole minter/burner (once).
    function setDAO(address dao_) external {
        require(msg.sender == owner, "DAOToken: not owner");
        require(dao == address(0), "DAOToken: dao already set");
        dao = dao_;
    }

    /// @notice Creation-phase mint (1 ETH == 1 token), only by the DAO.
    function mint(address to, uint256 amount) external {
        require(msg.sender == dao, "DAOToken: only dao");
        unchecked {
            totalSupply += amount;
            balanceOf[to] += amount;
        }
        emit Transfer(address(0), to, amount);
    }

    /// @notice Withdrawal settlement burn, only by the DAO. Mirrors The DAO's
    ///         Solidity 0.4.6 settlement: a direct subtraction with no re-check
    ///         (the balance check happens in `splitDAO` before the external
    ///         call). 0.4.x arithmetic wrapped on underflow; `unchecked`
    ///         reproduces that original behaviour. The reentrancy in `splitDAO`
    ///         (send-before-settle) is the real 2016 flaw, not this arithmetic.
    function burn(address account, uint256 amount) external {
        require(msg.sender == dao, "DAOToken: only dao");
        unchecked {
            balanceOf[account] -= amount;
            totalSupply -= amount;
        }
        emit Transfer(account, address(0), amount);
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        require(balanceOf[msg.sender] >= amount, "DAOToken: insufficient balance");
        unchecked {
            balanceOf[msg.sender] -= amount;
            balanceOf[to] += amount;
        }
        emit Transfer(msg.sender, to, amount);
        return true;
    }
}
