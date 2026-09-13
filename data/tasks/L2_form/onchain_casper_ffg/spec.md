# Protocol modeling task

Model the protocol described below and analyze it. You may use any method
(Lean 4, Tamarin, Verifpal, or a combination of them). Deliverables follow the
task README: `verdict.json`, an attack report when a goal fails, and
machine-checkable evidence in your chosen tool.

**No model is provided.** You decide the strategy: formalize the whole protocol
first, or reason about the likely flaw and then prove it. The security goals you
must formulate should cover, at minimum: safety, accountable_safety, slashing_completeness.

---

## Protocol: Casper FFG (Ethereum finality)

**Category:** consensus

### Overview

Casper FFG overlays BFT finality on the chain: validators vote on checkpoint source/target pairs; two-thirds of stake finalizes a checkpoint. Slashing conditions punish equivocation and surround voting.

### Roles

- **Validators**
- **Beacon chain**
- **Attesters**

### Security goals (formulate each as a theorem/lemma)

| # | Goal name | Property |
|---|-----------|----------|
| 1 | `safety` | Two conflicting checkpoints cannot both be finalized without a slashing condition being violated. |
| 2 | `accountable_safety` | Violating safety implicates enough stake to be slashed. |
| 3 | `slashing_completeness` | Equivocation and surround votes are detectable and punished. |

### Threat model

Adversary controls up to 1/3 of stake; validators are rational and may equivocate.

### What to decide

Whether the goals hold for the deployed protocol as described. If a goal
fails, produce a concrete sequence of on-chain transactions/messages (an
attack trace) and the resulting violation. If you can, back it with a
machine-checked proof in your chosen tool.

### References

- Buterin & Griffith, Casper the Friendly Finality Gadget (2017)
- Ethereum consensus specs
