# Protocol modeling task

Model the protocol described below and analyze it. You may use any method
(Lean 4, Tamarin, Verifpal, or a combination of them). Deliverables follow the
task README: `verdict.json`, an attack report when a goal fails, and
machine-checkable evidence in your chosen tool.

**No model is provided.** You decide the strategy: formalize the whole protocol
first, or reason about the likely flaw and then prove it. The security goals you
must formulate should cover, at minimum: state_root_soundness, withdrawal_safety, data_availability, censorship_resistance.

---

## Protocol: Paradex

**Category:** layer2

### Overview

Paradex is a production on-chain layer2 protocol. Its deployed interfaces, message/transaction formats and parameters are the ground truth for this task; consult the protocol's documentation, deployment addresses and incident reports as needed.

### Roles

See the overview.

### Security goals (formulate each as a theorem/lemma)

| # | Goal name | Property |
|---|-----------|----------|
| 1 | `state_root_soundness` | Only valid state roots are finalized. |
| 2 | `withdrawal_safety` | Withdrawals release funds only against finalized valid state. |
| 3 | `data_availability` | The data needed to reconstruct state (and exit) is available. |
| 4 | `censorship_resistance` | Users can force-include transactions / exit even if the operator censors. |

### Threat model

The sequencer/operator is adversarial (censors, reorders, withholds data); at least one honest verifier/challenger is live unless stated otherwise.

### What to decide

Whether the goals hold for the deployed protocol as described. If a goal
fails, produce a concrete sequence of on-chain transactions/messages (an
attack trace) and the resulting violation. If you can, back it with a
machine-checked proof in your chosen tool.

### References

- https://ethereum.org/en/developers/docs/scaling/
- Rollup / L2 documentation
