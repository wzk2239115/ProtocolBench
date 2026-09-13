# Protocol modeling task

Model the protocol described below and analyze it. You may use any method
(Lean 4, Tamarin, Verifpal, or a combination of them). Deliverables follow the
task README: `verdict.json`, an attack report when a goal fails, and
machine-checkable evidence in your chosen tool.

**No model is provided.** You decide the strategy: formalize the whole protocol
first, or reason about the likely flaw and then prove it. The security goals you
must formulate should cover, at minimum: batch_validity, escape_hatch.

---

## Protocol: dYdX / StarkEx (validity exchange)

**Category:** layer2

### Overview

StarkEx batches off-chain trades and settles with a STARK proof; an on-chain operator manages deposits/withdrawals and a delayed-withdrawal escape hatch.

### Roles

- **Operator**
- **Prover**
- **L1 contract**

### Security goals (formulate each as a theorem/lemma)

| # | Goal name | Property |
|---|-----------|----------|
| 1 | `batch_validity` | Only valid batches with proofs update balances. |
| 2 | `escape_hatch` | Users can always withdraw via the on-chain delayed path even if the operator disappears. |

### Threat model

Adversary compromises the operator; cannot forge STARK proofs.

### What to decide

Whether the goals hold for the deployed protocol as described. If a goal
fails, produce a concrete sequence of on-chain transactions/messages (an
attack trace) and the resulting violation. If you can, back it with a
machine-checked proof in your chosen tool.

### References

- https://docs.starkware.co/
- StarkEx documentation
