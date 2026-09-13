# Protocol modeling task

Model the protocol described below and analyze it. You may use any method
(Lean 4, Tamarin, Verifpal, or a combination of them). Deliverables follow the
task README: `verdict.json`, an attack report when a goal fails, and
machine-checkable evidence in your chosen tool.

**No model is provided.** You decide the strategy: formalize the whole protocol
first, or reason about the likely flaw and then prove it. The security goals you
must formulate should cover, at minimum: assertion_correctness, challenger_liveness, bridge_consistency.

---

## Protocol: Arbitrum Rollup (multi-round fraud proof)

**Category:** layer2

### Overview

An optimistic rollup whose dispute game narrows a state assertion over multiple bisection rounds until a single instruction is executed on-chain.

### Roles

- **Sequencer**
- **Validator/challenger**
- **L1 bridge**

### Security goals (formulate each as a theorem/lemma)

| # | Goal name | Property |
|---|-----------|----------|
| 1 | `assertion_correctness` | Only correct post-states are confirmed after the dispute game. |
| 2 | `challenger_liveness` | An honest challenger can force resolution of a wrong assertion within the timeout. |
| 3 | `bridge_consistency` | L1-to-L2 withdrawals follow confirmed state only. |

### Threat model

Adversary controls the sequencer and can censor/delay, but at least one honest challenger is live.

### What to decide

Whether the goals hold for the deployed protocol as described. If a goal
fails, produce a concrete sequence of on-chain transactions/messages (an
attack trace) and the resulting violation. If you can, back it with a
machine-checked proof in your chosen tool.

### References

- https://docs.arbitrum.io/
- Arbitrum Nitro whitepaper
