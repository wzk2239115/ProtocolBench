# Protocol modeling task

Model the protocol described below and analyze it. You may use any method
(Lean 4, Tamarin, Verifpal, or a combination of them). Deliverables follow the
task README: `verdict.json`, an attack report when a goal fails, and
machine-checkable evidence in your chosen tool.

**No model is provided.** You decide the strategy: formalize the whole protocol
first, or reason about the likely flaw and then prove it. The security goals you
must formulate should cover, at minimum: safety, liveness.

---

## Protocol: Sui Narwhal/Bullshark

**Category:** consensus

### Overview

Sui separates data dissemination (Narwhal mempool DAG) from ordering (Bullshark BFT), giving high throughput with causal-order certificates.

### Roles

- **Validators**
- **Leaders**
- **DAG**

### Security goals (formulate each as a theorem/lemma)

| # | Goal name | Property |
|---|-----------|----------|
| 1 | `safety` | Validators agree on a total order of committed certificates. |
| 2 | `liveness` | With a correct leader and GST, commits proceed. |

### Threat model

Adversary controls <1/3 of stake and may be a leader in some rounds.

### What to decide

Whether the goals hold for the deployed protocol as described. If a goal
fails, produce a concrete sequence of on-chain transactions/messages (an
attack trace) and the resulting violation. If you can, back it with a
machine-checked proof in your chosen tool.

### References

- Bullshark (2022)
- https://docs.sui.io/
