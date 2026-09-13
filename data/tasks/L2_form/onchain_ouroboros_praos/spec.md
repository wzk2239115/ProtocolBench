# Protocol modeling task

Model the protocol described below and analyze it. You may use any method
(Lean 4, Tamarin, Verifpal, or a combination of them). Deliverables follow the
task README: `verdict.json`, an attack report when a goal fails, and
machine-checkable evidence in your chosen tool.

**No model is provided.** You decide the strategy: formalize the whole protocol
first, or reason about the likely flaw and then prove it. The security goals you
must formulate should cover, at minimum: common_prefix, chain_quality.

---

## Protocol: Ouroboros Praos (Cardano)

**Category:** consensus

### Overview

Praos is a proof-of-stake longest-chain protocol with a private leader election (VRF), epoch-based randomness, and a chain-selection rule weighted by stake; it tolerates adaptive corruption.

### Roles

- **Stake pools**
- **Delegators**
- **Nodes**

### Security goals (formulate each as a theorem/lemma)

| # | Goal name | Property |
|---|-----------|----------|
| 1 | `common_prefix` | Honest chains share a common prefix except for recent blocks. |
| 2 | `chain_quality` | Adversarial chains cannot grow faster than honest chains under the stake bound. |

### Threat model

Adversary controls <1/2 of stake and can corrupt parties adaptively (with delay).

### What to decide

Whether the goals hold for the deployed protocol as described. If a goal
fails, produce a concrete sequence of on-chain transactions/messages (an
attack trace) and the resulting violation. If you can, back it with a
machine-checked proof in your chosen tool.

### References

- Kiayias et al., Ouroboros Praos (EUROCRYPT 2017)
