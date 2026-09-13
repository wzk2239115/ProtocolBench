# Protocol modeling task

Model the protocol described below and analyze it. You may use any method
(Lean 4, Tamarin, Verifpal, or a combination of them). Deliverables follow the
task README: `verdict.json`, an attack report when a goal fails, and
machine-checkable evidence in your chosen tool.

**No model is provided.** You decide the strategy: formalize the whole protocol
first, or reason about the likely flaw and then prove it. The security goals you
must formulate should cover, at minimum: safety, liveness.

---

## Protocol: Avalanche Snowman Consensus

**Category:** consensus

### Overview

Avalanche uses repeated sub-sampled voting (Snowball) to build confidence; Snowman linearizes it into a chain with a preference/confidence counter and finality after a confidence threshold.

### Roles

- **Validators**
- **Nodes**

### Security goals (formulate each as a theorem/lemma)

| # | Goal name | Property |
|---|-----------|----------|
| 1 | `safety` | Two conflicting blocks cannot both reach finality under the honest-stake bound. |
| 2 | `liveness` | The network reaches finality when enough honest validators participate. |

### Threat model

Adversary controls a bounded fraction of stake and can delay messages.

### What to decide

Whether the goals hold for the deployed protocol as described. If a goal
fails, produce a concrete sequence of on-chain transactions/messages (an
attack trace) and the resulting violation. If you can, back it with a
machine-checked proof in your chosen tool.

### References

- Rocket, Snowflake to Avalanche (2018)
- https://docs.avax.network/
