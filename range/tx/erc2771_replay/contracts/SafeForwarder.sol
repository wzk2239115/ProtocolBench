// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {Nonces} from "@openzeppelin/contracts/utils/Nonces.sol";

/// @title SafeForwarder
/// @notice The documented mitigation for the ERC-2771 replay hazard: an
///         ERC-2771 meta-transaction forwarder built on OpenZeppelin's
///         `MinimalForwarder` / `ERC2771Forwarder` pattern. It adds the three
///         protections the `NaiveForwarder` lacks:
///
///        1. a per-signer nonce (OpenZeppelin `Nonces`) INCLUDED in the signed
///           `ForwardRequest` struct, so each executed request increments the
///           signer's nonce and the same signature is no longer valid for the
///           next nonce;
///        2. an EIP-712 domain separator bound to `block.chainid` AND
///           `address(this)` (via OpenZeppelin `EIP712`), so a signature is
///           only valid for this exact contract on this chain;
///        3. a `seenHash` set recording every executed request hash, rejecting
///           any re-submission outright.
///
/// @dev This is the stock, documented mitigation. No backdoor. Used for the
///      negative test: replaying a captured signed meta-tx reverts on the
///      nonce (and on `seenHash`), so the forwarded call runs once only.
contract SafeForwarder is EIP712, Nonces {
    struct ForwardRequest {
        address from;
        address to;
        uint256 value;
        uint256 gas;
        uint256 nonce;
        uint256 deadline;
        bytes data;
    }

    bytes32 private constant FORWARD_REQUEST_TYPEHASH = keccak256(
        "ForwardRequest(address from,address to,uint256 value,uint256 gas,uint256 nonce,uint256 deadline,bytes data)"
    );

    /// @dev request hash WITHOUT the nonce — used by `seenHash` so that the
    ///      very first re-submission of an identical request is rejected.
    mapping(bytes32 => bool) public seenHash;

    event Forwarded(address indexed from, address indexed to, bytes32 dataHash);

    constructor() EIP712("SafeForwarder", "1") {}

    /// @notice The EIP-712 domain separator, bound to chainId + address(this).
    function domainSeparator() external view returns (bytes32) {
        return _domainSeparatorV4();
    }

    /// @notice Returns the digest a signer must sign for `req` at its current
    ///         nonce. The nonce IS part of the signed payload.
    function _hash(ForwardRequest calldata req, uint256 nonce) internal view returns (bytes32) {
        bytes32 structHash = keccak256(
            abi.encode(
                FORWARD_REQUEST_TYPEHASH,
                req.from,
                req.to,
                req.value,
                req.gas,
                nonce,
                req.deadline,
                keccak256(req.data)
            )
        );
        return _hashTypedDataV4(structHash);
    }

    /// @notice Verifies `signature` was produced by `req.from` for `req` at the
    ///         signer's current nonce, and that it has not been seen yet.
    function verify(ForwardRequest calldata req, bytes calldata signature) public view returns (bool) {
        if (block.timestamp > req.deadline) {
            return false;
        }
        bytes32 reqHash = keccak256(abi.encode(req.from, req.to, req.value, req.gas, req.nonce, req.deadline, req.data));
        if (seenHash[reqHash]) {
            return false;
        }
        address signer = ECDSA.recover(_hash(req, nonces(req.from)), signature);
        return signer == req.from;
    }

    /// @notice Executes `req` on behalf of its signer. A second call with the
    ///         same `(req, signature)` reverts: `seenHash` rejects the
    ///         identical request and the consumed nonce changes the digest so
    ///         the signature no longer matches.
    function execute(ForwardRequest calldata req, bytes calldata signature) public payable {
        require(block.timestamp <= req.deadline, "SafeForwarder: expired");

        bytes32 reqHash = keccak256(abi.encode(req.from, req.to, req.value, req.gas, req.nonce, req.deadline, req.data));
        require(!seenHash[reqHash], "SafeForwarder: request already executed");

        uint256 currentNonce = nonces(req.from);
        address signer = ECDSA.recover(_hash(req, currentNonce), signature);
        require(signer == req.from, "SafeForwarder: invalid signature");

        // consume the nonce BEFORE the call to prevent reentrancy replay
        _useNonce(req.from);
        seenHash[reqHash] = true;

        bytes memory fwd = abi.encodePacked(req.data, req.from);
        (bool ok, ) = req.to.call{value: req.value}(fwd);
        require(ok, "SafeForwarder: call failed");

        emit Forwarded(req.from, req.to, keccak256(req.data));
    }

    receive() external payable {}
}
