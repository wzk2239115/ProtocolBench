# Protocol modeling task

Model the protocol described below and analyze it. You may use any method
(Lean 4, Tamarin, Verifpal, or a combination of them). Deliverables follow the
task README: `verdict.json`, an attack report when a goal fails, and
machine-checkable evidence in your chosen tool.

**No model is provided.** You decide the strategy: formalize the whole protocol
first, or reason about the likely flaw and then prove it. The security goals you
must formulate should cover, at minimum: solvency_invariant, liquidation_correctness, oracle_soundness.

---

## Protocol: Euler V2

**Category:** lending

### Overview

Euler V2 is a production on-chain lending protocol. Its deployed interfaces, message/transaction formats and parameters are the ground truth for this task; consult the protocol's documentation, deployment addresses and incident reports as needed.

### Roles

See the overview.

### Security goals (formulate each as a theorem/lemma)

| # | Goal name | Property |
|---|-----------|----------|
| 1 | `solvency_invariant` | No account's debt exceeds its collateral value times the allowed factor. |
| 2 | `liquidation_correctness` | Liquidations execute only for undercollateralized accounts and keep the market solvent. |
| 3 | `oracle_soundness` | The price feed cannot be manipulated to borrow or liquidate unfairly. |

### Threat model

Adversary is a borrower/liquidator with flash loans; may manipulate an oracle or exploit interest-index timing.

### What to decide

Whether the goals hold for the deployed protocol as described. If a goal
fails, produce a concrete sequence of on-chain transactions/messages (an
attack trace) and the resulting violation. If you can, back it with a
machine-checked proof in your chosen tool.

### References

- Lending protocol docs / whitepaper
