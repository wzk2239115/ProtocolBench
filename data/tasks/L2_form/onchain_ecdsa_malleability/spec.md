# Protocol modeling task

Model the protocol described below and analyze it. You may use any method
(Lean 4, Tamarin, Verifpal, or a combination of them). Deliverables follow the
task README: `verdict.json`, an attack report when a goal fails, and
machine-checkable evidence in your chosen tool.

**No model is provided.** You decide the strategy: formalize the whole protocol
first, or reason about the likely flaw and then prove it. The security goals you
must formulate should cover, at minimum: signature_uniqueness, txid_stability.

---

## Protocol: ECDSA Signature Malleability

**Category:** signature

### Overview

ECDSA signatures (r, s) have a second valid representation (r, n-s) for the same message and key. Bitcoin's original txid was the signature, so malleated signatures changed the txid.

### Roles

- **Signer**
- **Verifier**
- **Transaction**

### Security goals (formulate each as a theorem/lemma)

| # | Goal name | Property |
|---|-----------|----------|
| 1 | `signature_uniqueness` | For a fixed key and message there is exactly one canonical valid signature. |
| 2 | `txid_stability` | Mutating the signature cannot change a transaction's identifier without invalidating it. |

### Threat model

Adversary can observe a broadcast transaction and mutate the signature encoding.

### What to decide

Whether the goals hold for the deployed protocol as described. If a goal
fails, produce a concrete sequence of on-chain transactions/messages (an
attack trace) and the resulting violation. If you can, back it with a
machine-checked proof in your chosen tool.

### References

- https://en.bitcoin.it/wiki/Transaction_malleability
- BIP-62/BIP-141 (SegWit)
