# Protocol modeling task

Model the protocol described below and analyze it. You may use any method
(Lean 4, Tamarin, Verifpal, or a combination of them). Deliverables follow the
task README: `verdict.json`, an attack report when a goal fails, and
machine-checkable evidence in your chosen tool.

**No model is provided.** You decide the strategy: formalize the whole protocol
first, or reason about the likely flaw and then prove it. The security goals you
must formulate should cover, at minimum: peg_solvency, custody_safety, redemption_liveness.

---

## Protocol: Ethena USDe (delta-neutral stablecoin)

**Category:** stablecoin

### Overview

USDe is backed by delta-neutral positions: staked ETH plus a short perpetual future; the funding rate and counterparty/exchange risk determine solvency, with an insurance fund and mint/redeem.

### Roles

- **Minter/redeemer**
- **Ethena protocol**
- **Custodian/exchange**

### Security goals (formulate each as a theorem/lemma)

| # | Goal name | Property |
|---|-----------|----------|
| 1 | `peg_solvency` | USDe remains fully backed under funding-rate and basis moves. |
| 2 | `custody_safety` | Collateral held off-chain at custodians/exchanges cannot be lost or double-used. |
| 3 | `redemption_liveness` | USDe can be redeemed when markets are open. |

### Threat model

Adversary exploits exchange/custodian risk, negative funding, or a basis blowout; the protocol relies on off-chain counterparties.

### What to decide

Whether the goals hold for the deployed protocol as described. If a goal
fails, produce a concrete sequence of on-chain transactions/messages (an
attack trace) and the resulting violation. If you can, back it with a
machine-checked proof in your chosen tool.

### References

- https://docs.ethena.fi/
