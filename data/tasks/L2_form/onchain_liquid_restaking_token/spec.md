# Protocol modeling task

Model the protocol described below and analyze it. You may use any method
(Lean 4, Tamarin, Verifpal, or a combination of them). Deliverables follow the
task README: `verdict.json`, an attack report when a goal fails, and
machine-checkable evidence in your chosen tool.

**No model is provided.** You decide the strategy: formalize the whole protocol
first, or reason about the likely flaw and then prove it. The security goals you
must formulate should cover, at minimum: balance_integrity, allowance_correctness, transfer_authorization.

---

## Protocol: Liquid Restaking Token

**Category:** token

### Overview

Liquid Restaking Token is a production on-chain token protocol. Its deployed interfaces, message/transaction formats and parameters are the ground truth for this task; consult the protocol's documentation, deployment addresses and incident reports as needed.

### Roles

See the overview.

### Security goals (formulate each as a theorem/lemma)

| # | Goal name | Property |
|---|-----------|----------|
| 1 | `balance_integrity` | Balances and total supply are conserved across transfers and mint/burn. |
| 2 | `allowance_correctness` | Spending is bounded by the owner's allowance and not reusable. |
| 3 | `transfer_authorization` | Only the owner / approved spender can transfer. |

### Threat model

Adversary is a spender/operator exploiting approval semantics, hooks, or ordering.

### What to decide

Whether the goals hold for the deployed protocol as described. If a goal
fails, produce a concrete sequence of on-chain transactions/messages (an
attack trace) and the resulting violation. If you can, back it with a
machine-checked proof in your chosen tool.

### References

- Token standard documentation
