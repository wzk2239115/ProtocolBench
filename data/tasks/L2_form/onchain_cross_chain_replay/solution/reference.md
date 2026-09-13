# Reference: cross-chain signed-transaction replay

**Verdict: UNSAFE.** The replay-protection failure observed at the 2016
Ethereum/Ethereum-Classic split; fixed by EIP-155.

## Root cause

The signature covers `(nonce, gasPrice, gasLimit, to, value, data)` but not the
chain id. At a split, both chains share the same account state and the same
signature-verification rules, so a transaction valid on chain A is valid on
chain B. There is no chain-scoped uniqueness for the signature.

## Attack

1. Victim signs `tx` and broadcasts it on chain A.
2. Chain A includes `tx`; the victim's balance decreases and `nonce += 1`.
3. Adversary re-broadcasts the identical signed `tx` on chain B.
4. Chain B checks the signature (valid), the nonce (still the old value on
   chain B, since B never saw the transaction), and includes it. The victim's
   balance on chain B decreases as well.

On a chain split the transaction can be replayed once per chain; the same
signature also enables replay of contract-call side effects.

## Fix

- EIP-155: include a chain identifier in the signed payload
  (`v` encodes `chainId`), so a signature is valid only on its intended chain.
- Alternatively bind the signature to a domain separator
  `(chainId, verifyingContract)` as in EIP-712 for replay-safe typed data.
