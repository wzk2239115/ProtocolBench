# Protocol modeling task

Model the protocol described below and analyze it. You may use any method
(Lean 4, Tamarin, Verifpal, or a combination of them). Deliverables follow the
task README: `verdict.json`, an attack report when a goal fails, and
machine-checkable evidence in your chosen tool.

**No model is provided.** You decide the strategy: formalize the whole protocol
first, or reason about the likely flaw and then prove it. The security goals you
must formulate should cover, at minimum: vote_binding, gauge_emission_correctness, no_flash_governance.

---

## Protocol: Curve veCRV Vote-Buying / bribe markets

**Category:** governance

### Overview

Curve locks CRV for veCRV to direct emissions to gauges; bribe markets (e.g. Convex/Votium) let others pay for votes, and Convex aggregates veCRV for voting power.

### Roles

- **Voter**
- **Gauge**
- **Bribe market**
- **Convex**

### Security goals (formulate each as a theorem/lemma)

| # | Goal name | Property |
|---|-----------|----------|
| 1 | `vote_binding` | Locked votes cannot be double-counted or replayed after delegation. |
| 2 | `gauge_emission_correctness` | Emissions follow the recorded vote weights. |
| 3 | `no_flash_governance` | Voting power cannot be obtained flash-loan-like for a single epoch. |

### Threat model

Adversary acquires voting power atomically or exploits vote-delegation/accounting.

### What to decide

Whether the goals hold for the deployed protocol as described. If a goal
fails, produce a concrete sequence of on-chain transactions/messages (an
attack trace) and the resulting violation. If you can, back it with a
machine-checked proof in your chosen tool.

### References

- https://docs.curve.fi/
- Curve veCRV/gauges
