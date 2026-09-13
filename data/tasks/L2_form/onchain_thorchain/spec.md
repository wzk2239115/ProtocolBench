# Protocol modeling task

Model the protocol described below and analyze it. You may use any method
(Lean 4, Tamarin, Verifpal, or a combination of them). Deliverables follow the
task README: `verdict.json`, an attack report when a goal fails, and
machine-checkable evidence in your chosen tool.

**No model is provided.** You decide the strategy: formalize the whole protocol
first, or reason about the likely flaw and then prove it. The security goals you
must formulate should cover, at minimum: inbound_outbound_consistency, pool_value_soundness.

---

## Protocol: THORChain (cross-chain swaps)

**Category:** bridge

### Overview

THORChain uses a rotating validator set (vaults) to custody assets and uses continuous liquidity pools with a slip-based fee; inbound/outbound observations drive state changes.

### Roles

- **Validators**
- **Vault**
- **Trader**

### Security goals (formulate each as a theorem/lemma)

| # | Goal name | Property |
|---|-----------|----------|
| 1 | `inbound_outbound_consistency` | Outbound amounts match observed intents and pool accounting. |
| 2 | `pool_value_soundness` | Pool balances cannot be manipulated to over-withdraw. |

### Threat model

Adversary manipulates gas accounting/observation or pool math; may exploit donation/accounting during churn.

### What to decide

Whether the goals hold for the deployed protocol as described. If a goal
fails, produce a concrete sequence of on-chain transactions/messages (an
attack trace) and the resulting violation. If you can, back it with a
machine-checked proof in your chosen tool.

### References

- THORChain 2021 incidents
- https://docs.thorchain.org/
