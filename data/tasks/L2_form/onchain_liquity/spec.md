# Protocol modeling task

Model the protocol described below and analyze it. You may use any method
(Lean 4, Tamarin, Verifpal, or a combination of them). Deliverables follow the
task README: `verdict.json`, an attack report when a goal fails, and
machine-checkable evidence in your chosen tool.

**No model is provided.** You decide the strategy: formalize the whole protocol
first, or reason about the likely flaw and then prove it. The security goals you
must formulate should cover, at minimum: trove_solvency, redemption_soundness.

---

## Protocol: Liquity (LUSD troves)

**Category:** stablecoin

### Overview

Liquity issues LUSD against ETH collateral in troves. Stability is maintained by a Stability Pool, liquidations (with gas compensation), a recovery mode, and redemptions of LUSD against the riskiest troves.

### Roles

- **Borrower**
- **Stability-pool depositor**
- **Liquidator**
- **Redeemer**

### Security goals (formulate each as a theorem/lemma)

| # | Goal name | Property |
|---|-----------|----------|
| 1 | `trove_solvency` | A trove stays above the minimum collateral ratio unless liquidated. |
| 2 | `redemption_soundness` | Redemptions always reduce total debt and transfer exactly the redeemed collateral. |

### Threat model

Adversary manipulates the ETH price feed or exploits liquidation/recovery-mode transitions.

### What to decide

Whether the goals hold for the deployed protocol as described. If a goal
fails, produce a concrete sequence of on-chain transactions/messages (an
attack trace) and the resulting violation. If you can, back it with a
machine-checked proof in your chosen tool.

### References

- https://docs.liquity.org/
- Liquity whitepaper
