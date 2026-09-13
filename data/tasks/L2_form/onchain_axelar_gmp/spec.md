# Protocol modeling task

Model the protocol described below and analyze it. You may use any method
(Lean 4, Tamarin, Verifpal, or a combination of them). Deliverables follow the
task README: `verdict.json`, an attack report when a goal fails, and
machine-checkable evidence in your chosen tool.

**No model is provided.** You decide the strategy: formalize the whole protocol
first, or reason about the likely flaw and then prove it. The security goals you
must formulate should cover, at minimum: message_authenticity, command_uniqueness, approval_correctness.

---

## Protocol: Axelar General Message Passing

**Category:** interop

### Overview

Axelar is a PoS validator network that observes source-chain events and signs cross-chain messages executed by a gateway on the destination chain.

### Roles

- **Validators**
- **Gateway**
- **Gas service**
- **dApp**

### Security goals (formulate each as a theorem/lemma)

| # | Goal name | Property |
|---|-----------|----------|
| 1 | `message_authenticity` | A command executes only if signed by the Axelar validator quorum for the source chain. |
| 2 | `command_uniqueness` | A command id executes at most once. |
| 3 | `approval_correctness` | Token approval/transfer amounts follow the source lock/burn. |

### Threat model

Adversary controls <1/3 of validator stake; may exploit command-id replay or approval-encoding bugs.

### What to decide

Whether the goals hold for the deployed protocol as described. If a goal
fails, produce a concrete sequence of on-chain transactions/messages (an
attack trace) and the resulting violation. If you can, back it with a
machine-checked proof in your chosen tool.

### References

- https://docs.axelar.dev/
