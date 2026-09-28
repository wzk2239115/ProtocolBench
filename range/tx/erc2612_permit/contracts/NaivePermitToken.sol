// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {IERC20Permit} from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Permit.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {Nonces} from "@openzeppelin/contracts/utils/Nonces.sol";

/// @title NaivePermitToken
/// @notice An ERC-20 + ERC-2612 `permit` extension where the EIP-712
///         `DOMAIN_SEPARATOR` is HARDCODED: it is derived from the token name
///         and a fixed version / chainId, but the `verifyingContract` field is
///         set to `address(0)` instead of `address(this)`, and `chainId` is a
///         fixed constant instead of `block.chainid`.
///
/// @dev This is the real, documented ERC-2612 weak-domain-binding design. The
///      EIP-712 specification states the domain separator SHOULD include the
///      verifying contract address (and chain id) to prevent cross-contract
///      and cross-chain replay of signed typed data. Because this contract's
///      domain separator does NOT depend on `address(this)`, every deployment
///      of this token with the same name produces the SAME domain separator,
///      and a `permit` signature that is valid for one deployment is valid for
///      every other deployment on any chain — the signature can be replayed to
///      grant an allowance the owner never intended for that deployment. No
///      injected bug, no backdoor; the hazard is the missing address / chain
///      binding in the domain separator, faithfully reproduced here.
contract NaivePermitToken is ERC20, IERC20Permit, Nonces {
    bytes32 private constant EIP712_DOMAIN_TYPEHASH = keccak256(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    );
    bytes32 private constant PERMIT_TYPEHASH = keccak256(
        "Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)"
    );

    /// @dev The hardcoded domain separator. NOT bound to `address(this)` or
    ///      `block.chainid` — the real flaw. Computed once in the constructor.
    bytes32 private immutable _domainSeparator;

    constructor(
        string memory name_,
        string memory symbol_,
        uint256 initialSupply
    ) ERC20(name_, symbol_) {
        _mint(msg.sender, initialSupply);
        _domainSeparator = keccak256(abi.encode(
            EIP712_DOMAIN_TYPEHASH,
            keccak256(bytes(name_)),
            keccak256(bytes("1")),
            uint256(1), // FIXED chainId — not block.chainid
            address(0) // THE FLAW: not address(this)
        ));
    }

    /// @inheritdoc IERC20Permit
    function permit(
        address owner,
        address spender,
        uint256 value,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) public virtual {
        require(block.timestamp <= deadline, "ERC2612: expired");

        bytes32 structHash = keccak256(
            abi.encode(PERMIT_TYPEHASH, owner, spender, value, _useNonce(owner), deadline)
        );
        bytes32 digest = keccak256(abi.encodePacked(hex"1901", _domainSeparator, structHash));
        address signer = ECDSA.recover(digest, v, r, s);
        require(signer == owner, "ERC2612: invalid signature");

        _approve(owner, spender, value);
    }

    /// @inheritdoc IERC20Permit
    function nonces(address owner) public view virtual override(IERC20Permit, Nonces) returns (uint256) {
        return super.nonces(owner);
    }

    /// @inheritdoc IERC20Permit
    // solhint-disable-next-line func-name-mixedcase
    function DOMAIN_SEPARATOR() external view virtual returns (bytes32) {
        return _domainSeparator;
    }
}
