# Protocol modeling task

Model the protocol described below and analyze it. You may use any method
(Lean 4, Tamarin, Verifpal, or a combination of them). Deliverables follow the
task README: `verdict.json`, an attack report when a goal fails, and
machine-checkable evidence in your chosen tool.

**No model is provided.** You decide the strategy: formalize the whole protocol
first, or reason about the likely flaw and then prove it. The security goals you
must formulate should cover, at minimum: validity_soundness, withdrawal_consistency.

---

## Protocol: zkSync Era

**Category:** layer2

### Overview

A zkEVM rollup posting state diffs with a validity proof verified on L1; a sequencer orders transactions and a prover generates SNARKs.

### Roles

- **Sequencer**
- **Prover**
- **L1 verifier**

### Security goals (formulate each as a theorem/lemma)

| # | Goal name | Property |
|---|-----------|----------|
| 1 | `validity_soundness` | Only valid state diffs accepted by the verifier are finalized. |
| 2 | `withdrawal_consistency` | L1 withdrawals correspond to proven L2 state. |

### Threat model

Adversary cannot break the proof system; may censor or withhold data.

### What to decide

Whether the goals hold for the deployed protocol as described. If a goal
fails, produce a concrete sequence of on-chain transactions/messages (an
attack trace) and the resulting violation. If you can, back it with a
machine-checked proof in your chosen tool.

### References

- https://docs.zksync.io/
- zkSync Era documentation
