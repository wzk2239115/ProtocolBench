# Protocol modeling task

Model the protocol described below and analyze it. You may use any method
(Lean 4, Tamarin, Verifpal, or a combination of them). Deliverables follow the
task README: `verdict.json`, an attack report when a goal fails, and
machine-checkable evidence in your chosen tool.

**No model is provided.** You decide the strategy: formalize the whole protocol
first, or reason about the likely flaw and then prove it. The security goals you
must formulate should cover, at minimum: peg_solvency, backing_integrity, mint_authorization.

---

## Protocol: alUSD

**Category:** stablecoin

### Overview

alUSD is a production on-chain stablecoin protocol. Its deployed interfaces, message/transaction formats and parameters are the ground truth for this task; consult the protocol's documentation, deployment addresses and incident reports as needed.

### Roles

See the overview.

### Security goals (formulate each as a theorem/lemma)

| # | Goal name | Property |
|---|-----------|----------|
| 1 | `peg_solvency` | The stablecoin is fully backed by protocol collateral / collateralized positions. |
| 2 | `backing_integrity` | Collateral cannot be double-counted or rehypothecated. |
| 3 | `mint_authorization` | Only authorized paths can mint or redeem. |

### Threat model

Adversary manipulates collateral prices, oracle feeds, or redemption paths; may exploit privileged roles.

### What to decide

Whether the goals hold for the deployed protocol as described. If a goal
fails, produce a concrete sequence of on-chain transactions/messages (an
attack trace) and the resulting violation. If you can, back it with a
machine-checked proof in your chosen tool.

### References

- Stablecoin protocol docs
