# Protocol modeling task

Model the protocol described below and analyze it. You may use any method
(Lean 4, Tamarin, Verifpal, or a combination of them). Deliverables follow the
task README: `verdict.json`, an attack report when a goal fails, and
machine-checkable evidence in your chosen tool.

**No model is provided.** You decide the strategy: formalize the whole protocol
first, or reason about the likely flaw and then prove it. The security goals you
must formulate should cover, at minimum: checkpoint_quorum, exit_validity.

---

## Protocol: Polygon PoS (checkpoint bridge)

**Category:** layer2

### Overview

A PoS sidechain whose checkpoints are submitted to Ethereum by a validator set; an on-chain bridge (Plasma/PoS portal) locks and releases assets.

### Roles

- **Bor/Heimdall validators**
- **Checkpoint bridge**
- **RootChainManager**

### Security goals (formulate each as a theorem/lemma)

| # | Goal name | Property |
|---|-----------|----------|
| 1 | `checkpoint_quorum` | A checkpoint is accepted only with 2/3 validator power. |
| 2 | `exit_validity` | Withdrawals require a valid burn proof against a checkpointed root. |

### Threat model

Adversary controls <2/3 stake; may exploit exit-proof encoding/validation.

### What to decide

Whether the goals hold for the deployed protocol as described. If a goal
fails, produce a concrete sequence of on-chain transactions/messages (an
attack trace) and the resulting violation. If you can, back it with a
machine-checked proof in your chosen tool.

### References

- https://docs.polygon.technology/pos/
