# Protocol modeling task

Model the protocol described below and analyze it. You may use any method
(Lean 4, Tamarin, Verifpal, or a combination of them). Deliverables follow the
task README: `verdict.json`, an attack report when a goal fails, and
machine-checkable evidence in your chosen tool.

**No model is provided.** You decide the strategy: formalize the whole protocol
first, or reason about the likely flaw and then prove it. The security goals you
must formulate should cover, at minimum: exit_soundness, mass_exit_safety, challenge_liveness.

---

## Protocol: Plasma (exit game)

**Category:** layer2

### Overview

Plasma chains commit block roots to a parent chain; users exit by a proof and a challenge period during which other users can challenge invalid exits.

### Roles

- **Operator**
- **User**
- **Parent chain**

### Security goals (formulate each as a theorem/lemma)

| # | Goal name | Property |
|---|-----------|----------|
| 1 | `exit_soundness` | Only funds the exiting user owns can leave via an exit. |
| 2 | `mass_exit_safety` | If the operator withholds data, honest users can still exit. |
| 3 | `challenge_liveness` | Invalid exits can be challenged within the period. |

### Threat model

Adversary controls the operator and may withhold data or spam exits (exit griefing).

### What to decide

Whether the goals hold for the deployed protocol as described. If a goal
fails, produce a concrete sequence of on-chain transactions/messages (an
attack trace) and the resulting violation. If you can, back it with a
machine-checked proof in your chosen tool.

### References

- https://plasma.io/
- Plasma whitepaper
