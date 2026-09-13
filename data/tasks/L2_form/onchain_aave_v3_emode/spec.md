# Protocol modeling task

Model the protocol described below and analyze it. You may use any method
(Lean 4, Tamarin, Verifpal, or a combination of them). Deliverables follow the
task README: `verdict.json`, an attack report when a goal fails, and
machine-checkable evidence in your chosen tool.

**No model is provided.** You decide the strategy: formalize the whole protocol
first, or reason about the likely flaw and then prove it. The security goals you
must formulate should cover, at minimum: emode_soundness, debt_ceiling_enforcement, oracle_consistency.

---

## Protocol: Aave V3 E-Mode and Isolation Mode

**Category:** lending

### Overview

Aave V3 adds efficiency mode (higher LTV within correlated assets) and isolation mode (new assets can only be borrowed up to a debt ceiling, with limited collateral use).

### Roles

- **Supplier**
- **Borrower**
- **Liquidator**

### Security goals (formulate each as a theorem/lemma)

| # | Goal name | Property |
|---|-----------|----------|
| 1 | `emode_soundness` | E-mode LTV is only granted to correlated assets and liquidation remains possible. |
| 2 | `debt_ceiling_enforcement` | Isolated assets cannot exceed their debt ceiling. |
| 3 | `oracle_consistency` | Price feeds are consistent across correlated assets. |

### Threat model

Adversary exploits correlated-asset price divergence and oracle inconsistency; may be a governance/parameter attacker.

### What to decide

Whether the goals hold for the deployed protocol as described. If a goal
fails, produce a concrete sequence of on-chain transactions/messages (an
attack trace) and the resulting violation. If you can, back it with a
machine-checked proof in your chosen tool.

### References

- https://docs.aave.com/developers/
- Aave V3 whitepaper
