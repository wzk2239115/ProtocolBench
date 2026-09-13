# Protocol modeling task

Model the protocol described below and analyze it. You may use any method
(Lean 4, Tamarin, Verifpal, or a combination of them). Deliverables follow the
task README: `verdict.json`, an attack report when a goal fails, and
machine-checkable evidence in your chosen tool.

**No model is provided.** You decide the strategy: formalize the whole protocol
first, or reason about the likely flaw and then prove it. The security goals you
must formulate should cover, at minimum: settlement_soundness, fund_safety.

---

## Protocol: Loopring zkRollup

**Category:** layer2

### Overview

A zkRollup DEX with off-chain order matching and on-chain SNARK-verified settlement; L1 holds funds and verifies batches.

### Roles

- **Operator**
- **Prover**
- **L1 verifier**

### Security goals (formulate each as a theorem/lemma)

| # | Goal name | Property |
|---|-----------|----------|
| 1 | `settlement_soundness` | Only valid, operator-signed batches whose proofs verify settle. |
| 2 | `fund_safety` | L1 funds cannot be moved except by valid withdrawals. |

### Threat model

Adversary may compromise the operator/prover role but cannot break the SNARK.

### What to decide

Whether the goals hold for the deployed protocol as described. If a goal
fails, produce a concrete sequence of on-chain transactions/messages (an
attack trace) and the resulting violation. If you can, back it with a
machine-checked proof in your chosen tool.

### References

- https://docs.loopring.org/
