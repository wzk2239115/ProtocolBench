// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

/// @title NaiveForwarder
/// @notice An ERC-2771 meta-transaction forwarder that verifies an EIP-712
///         signature over a `ForwardRequest` but **without** any replay
///         protection: there is NO per-signer nonce in the signed payload, the
///         domain separator is NOT bound to `address(this)` / `block.chainid`,
///         and NO executed request hash is ever recorded.
///
/// @dev This is the real, documented ERC-2771 replay hazard. ERC-2771 itself
///      does not mandate replay protection; it only specifies how `_msgSender()`
///      is recovered from the calldata suffix. OpenZeppelin's own
///      `MinimalForwarder` / `ERC2771Forwarder` add an EIP-712 domain separator
///      bound to the verifying contract plus a per-signer nonce precisely to
///      close this gap. This forwarder omits all three mitigations:
///
///        1. the signed `ForwardRequest` struct contains `from, to, value, gas,
///           deadline, data` — NO `nonce`. The same `(request, signature)` pair
///           hashes to the same digest forever, so a single valid signature can
///           be re-submitted any number of times.
///        2. the EIP-712 `DOMAIN_SEPARATOR` is hardcoded (derived from a fixed
///           name/version, a fixed chainId of 1 and `verifyingContract =
///           address(0)`) instead of `block.chainid` / `address(this)`, so it
///           does not bind the signature to this contract or chain.
///        3. no `seenHash` / executed-request set is kept, so nothing rejects a
///           re-submitted request.
///
///      A captured signed meta-tx is therefore replayable: re-calling `execute`
///      with the same `(request, signature)` re-runs the forwarded call every
///      time. No injected bug, no backdoor — the flaw is the missing replay
///      protection, faithfully reproduced here.
contract NaiveForwarder {
    struct ForwardRequest {
        address from;
        address to;
        uint256 value;
        uint256 gas;
        uint256 nonce; // present in the struct for a uniform interface; NOT signed
        uint256 deadline;
        bytes data;
    }

    bytes32 private constant EIP712_DOMAIN_TYPEHASH = keccak256(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    );
    // NOTE: no `nonce` field — the real flaw.
    bytes32 private constant FORWARD_REQUEST_TYPEHASH = keccak256(
        "ForwardRequest(address from,address to,uint256 value,uint256 gas,uint256 deadline,bytes data)"
    );

    /// @dev Hardcoded domain separator, NOT bound to `address(this)` or
    ///      `block.chainid` — the real flaw.
    bytes32 public immutable domainSeparator;

    event Forwarded(address indexed from, address indexed to, bytes32 dataHash);

    constructor() {
        domainSeparator = keccak256(
            abi.encode(
                EIP712_DOMAIN_TYPEHASH,
                keccak256(bytes("NaiveForwarder")),
                keccak256(bytes("1")),
                uint256(1), // FIXED chainId — not block.chainid
                address(0) // THE FLAW: not address(this)
            )
        );
    }

    /// @notice Returns the digest a signer must sign for `req`.
    function _hash(ForwardRequest calldata req) internal view returns (bytes32) {
        bytes32 structHash = keccak256(
            abi.encode(
                FORWARD_REQUEST_TYPEHASH,
                req.from,
                req.to,
                req.value,
                req.gas,
                // req.nonce intentionally NOT included — the replay hole
                req.deadline,
                keccak256(req.data)
            )
        );
        return keccak256(abi.encodePacked(hex"1901", domainSeparator, structHash));
    }

    /// @notice Verifies `signature` was produced by `req.from` for `req`.
    function verify(ForwardRequest calldata req, bytes calldata signature) public view returns (bool) {
        if (block.timestamp > req.deadline) {
            return false;
        }
        address signer = ECDSA.recover(_hash(req), signature);
        return signer == req.from;
    }

    /// @notice Executes `req` on behalf of its signer. Replays the forwarded
    ///         call every time it is called with the same `(req, signature)`,
    ///         because nothing is recorded and no nonce is consumed.
    function execute(ForwardRequest calldata req, bytes calldata signature) public payable {
        require(block.timestamp <= req.deadline, "NaiveForwarder: expired");
        bytes32 digest = _hash(req);
        address signer = ECDSA.recover(digest, signature);
        require(signer == req.from, "NaiveForwarder: invalid signature");

        // NO nonce consumption, NO seenHash recording — replayable by design.
        bytes memory fwd = abi.encodePacked(req.data, req.from);
        (bool ok, ) = req.to.call{value: req.value}(fwd);
        require(ok, "NaiveForwarder: call failed");

        emit Forwarded(req.from, req.to, keccak256(req.data));
    }

    receive() external payable {}
}
