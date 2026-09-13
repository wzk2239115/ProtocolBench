# Protocol modeling task

Model the protocol described below and analyze it. You may use any method
(Lean 4, Tamarin, Verifpal, or a combination of them). Deliverables follow the
task README: `verdict.json`, an attack report when a goal fails, and
machine-checkable evidence in your chosen tool.

**No model is provided.** You decide the strategy: formalize the whole protocol
first, or reason about the likely flaw and then prove it. The security goals you
must formulate should cover, at minimum: vault_solvency, dai_backing.

---

## Protocol: MakerDAO Vat (DAI CDP engine)

**Category:** stablecoin

### Overview

MakerDAO's Vat holds collateral (ink) and debt (art) per vault, normalized by rates; ilks define debt ceilings, stability fees, and liquidation ratios. Liquidations auction collateral.

### Roles

- **Vault owner**
- **Keeper/liquidator**
- **Oracle**
- **Vat core**

### Security goals (formulate each as a theorem/lemma)

| # | Goal name | Property |
|---|-----------|----------|
| 1 | `vault_solvency` | A vault's debt never exceeds its collateral value times the liquidation ratio without being liquidated. |
| 2 | `dai_backing` | Total DAI issued is backed by total collateral and system surplus. |

### Threat model

Adversary manipulates oracle prices or races liquidations; cannot mint unbacked DAI without authorization.

### What to decide

Whether the goals hold for the deployed protocol as described. If a goal
fails, produce a concrete sequence of on-chain transactions/messages (an
attack trace) and the resulting violation. If you can, back it with a
machine-checked proof in your chosen tool.

### References

- https://docs.makerdao.com/
- MakerDAO whitepaper
