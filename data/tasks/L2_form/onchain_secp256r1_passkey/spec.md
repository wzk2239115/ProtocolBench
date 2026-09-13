# Protocol modeling task

Model the protocol described below and analyze it. You may use any method
(Lean 4, Tamarin, Verifpal, or a combination of them). Deliverables follow the
task README: `verdict.json`, an attack report when a goal fails, and
machine-checkable evidence in your chosen tool.

**No model is provided.** You decide the strategy: formalize the whole protocol
first, or reason about the likely flaw and then prove it. The security goals you
must formulate should cover, at minimum: key_binding, domain_binding, verifier_soundness.

---

## Protocol: secp256r1 / Passkey Smart Accounts

**Category:** signature

### Overview

Smart accounts verify WebAuthn/passkey signatures over secp256r1 (P-256), often via an on-chain P-256 verifier precompile or contract and a ReplaySafeHash domain.

### Roles

- **User (passkey)**
- **Smart account**
- **P-256 verifier**

### Security goals (formulate each as a theorem/lemma)

| # | Goal name | Property |
|---|-----------|----------|
| 1 | `key_binding` | Only the registered passkey public key can authorize actions. |
| 2 | `domain_binding` | Signatures are bound to the account and chain. |
| 3 | `verifier_soundness` | The P-256 verifier rejects malformed signatures. |

### Threat model

Adversary replays WebAuthn assertions or exploits a malformed-signature acceptance bug in the verifier.

### What to decide

Whether the goals hold for the deployed protocol as described. If a goal
fails, produce a concrete sequence of on-chain transactions/messages (an
attack trace) and the resulting violation. If you can, back it with a
machine-checked proof in your chosen tool.

### References

- WebAuthn
- RIP-7212 (P-256 precompile)
- ERC-4337 passkey accounts
