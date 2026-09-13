# Protocol modeling task

Model the protocol described below and analyze it. You may use any method
(Lean 4, Tamarin, Verifpal, or a combination of them). Deliverables follow the
task README: `verdict.json`, an attack report when a goal fails, and
machine-checkable evidence in your chosen tool.

**No model is provided.** You decide the strategy: formalize the whole protocol
first, or reason about the likely flaw and then prove it. The security goals you
must formulate should cover, at minimum: safety, liveness, fork_choice_coherence.

---

## Protocol: Ethereum Gasper (LMD-GHOST + FFG)

**Category:** consensus

### Overview

Gasper combines LMD-GHOST fork choice (latest-message-driven) with Casper FFG finality; attesters vote for a head and for source/target checkpoints; slashings punish surround/equivocation.

### Roles

- **Validators**
- **Attesters**
- **Proposers**

### Security goals (formulate each as a theorem/lemma)

| # | Goal name | Property |
|---|-----------|----------|
| 1 | `safety` | Conflicting checkpoints cannot be finalized without slashing. |
| 2 | `liveness` | With honest majority and synchrony, the chain finalizes. |
| 3 | `fork_choice_coherence` | LMD-GHOST does not let a minority reorg finalized history. |

### Threat model

Adversary controls <1/3 of stake for safety and <1/2 for liveness; may cause reorgs and balancing attacks.

### What to decide

Whether the goals hold for the deployed protocol as described. If a goal
fails, produce a concrete sequence of on-chain transactions/messages (an
attack trace) and the resulting violation. If you can, back it with a
machine-checked proof in your chosen tool.

### References

- https://ethereum.org/en/developers/docs/consensus-mechanisms/pos/
- Gasper (2018)
