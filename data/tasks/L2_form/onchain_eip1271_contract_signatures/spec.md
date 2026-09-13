# Protocol modeling task

Model the protocol described below and analyze it. You may use any method
(Lean 4, Tamarin, Verifpal, or a combination of them). Deliverables follow the
task README: `verdict.json`, an attack report when a goal fails, and
machine-checkable evidence in your chosen tool.

**No model is provided.** You decide the strategy: formalize the whole protocol
first, or reason about the likely flaw and then prove it. The security goals you
must formulate should cover, at minimum: signature_validation_soundness, reentrancy_safety, replay_binding.

---

## Protocol: EIP-1271 Contract Signatures

**Category:** signature

### Overview

EIP-1271 lets a contract validate a signature via isValidSignature(hash, signature), enabling smart-contract accounts (Safe, AA wallets) to sign.

### Roles

- **Contract signer**
- **Verifier dApp**

### Security goals (formulate each as a theorem/lemma)

| # | Goal name | Property |
|---|-----------|----------|
| 1 | `signature_validation_soundness` | isValidSignature returns the magic value only for genuinely authorized signatures. |
| 2 | `reentrancy_safety` | Verification cannot be used to reenter the verifier. |
| 3 | `replay_binding` | The signed hash is bound to the intended action/domain. |

### Threat model

Adversary is a malicious contract signer returning the magic value, or a relayer exploiting reentrancy during verification.

### What to decide

Whether the goals hold for the deployed protocol as described. If a goal
fails, produce a concrete sequence of on-chain transactions/messages (an
attack trace) and the resulting violation. If you can, back it with a
machine-checked proof in your chosen tool.

### References

- https://eips.ethereum.org/EIPS/eip-1271
