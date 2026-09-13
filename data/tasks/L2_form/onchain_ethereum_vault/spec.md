# Protocol modeling task

Model the protocol described below and analyze it. You may use any method
(Lean 4, Tamarin, Verifpal, or a combination of them). Deliverables follow the
task README: `verdict.json`, an attack report when a goal fails, and
machine-checkable evidence in your chosen tool.

**No model is provided.** You decide the strategy: formalize the whole protocol
first, or reason about the likely flaw and then prove it. The security goals you
must formulate should cover, at minimum: share_price_integrity, strategy_authorization, no_inflation_theft.

---

## Protocol: Ethereum Vault

**Category:** yield

### Overview

Ethereum Vault is a production on-chain yield protocol. Its deployed interfaces, message/transaction formats and parameters are the ground truth for this task; consult the protocol's documentation, deployment addresses and incident reports as needed.

### Roles

See the overview.

### Security goals (formulate each as a theorem/lemma)

| # | Goal name | Property |
|---|-----------|----------|
| 1 | `share_price_integrity` | Existing depositors' redeemable value is not diluted by others. |
| 2 | `strategy_authorization` | Only authorized strategies receive funds. |
| 3 | `no_inflation_theft` | Rounding/donation cannot be exploited for profit. |

### Threat model

Adversary is a depositor/strategist exploiting share math or strategy permissions.

### What to decide

Whether the goals hold for the deployed protocol as described. If a goal
fails, produce a concrete sequence of on-chain transactions/messages (an
attack trace) and the resulting violation. If you can, back it with a
machine-checked proof in your chosen tool.

### References

- Vault / yield protocol documentation
