# Protocol modeling task

Model the protocol described below and analyze it. You may use any method
(Lean 4, Tamarin, Verifpal, or a combination of them). Deliverables follow the
task README: `verdict.json`, an attack report when a goal fails, and
machine-checkable evidence in your chosen tool.

**No model is provided.** You decide the strategy: formalize the whole protocol
first, or reason about the likely flaw and then prove it. The security goals you
must formulate should cover, at minimum: safety, liveness.

---

## Protocol: Stellar Consensus Protocol

**Category:** consensus

### Overview

SCP uses federated Byzantine agreement: each node chooses quorum slices; statements are confirmed through a federated voting process over ballots, with externalize and quorum-intersection guarantees.

### Roles

- **Nodes**
- **Quorum slices**

### Security goals (formulate each as a theorem/lemma)

| # | Goal name | Property |
|---|-----------|----------|
| 1 | `safety` | Two intact nodes cannot externalize conflicting values when quorum intersection holds. |
| 2 | `liveness` | Transitive quorum-closure and a correct node drive the protocol to confirmation. |

### Threat model

Adversary controls some nodes; the quorum system must have adequate intersection.

### What to decide

Whether the goals hold for the deployed protocol as described. If a goal
fails, produce a concrete sequence of on-chain transactions/messages (an
attack trace) and the resulting violation. If you can, back it with a
machine-checked proof in your chosen tool.

### References

- Mazieres, The Stellar Consensus Protocol (2015)
