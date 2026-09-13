# Protocol modeling task

Model the protocol described below and analyze it. You may use any method
(Lean 4, Tamarin, Verifpal, or a combination of them). Deliverables follow the
task README: `verdict.json`, an attack report when a goal fails, and
machine-checkable evidence in your chosen tool.

**No model is provided.** You decide the strategy: formalize the whole protocol
first, or reason about the likely flaw and then prove it. The security goals you
must formulate should cover, at minimum: share_price_monotonicity, no_inflation_theft.

---

## Protocol: ERC-4626 Tokenized Vault (share inflation)

**Category:** defi

### Overview

ERC-4626 standardizes yield vaults: deposit(assets) mints shares = assets * totalSupply / totalAssets; redeem burns shares for assets. First depositor sets the initial share price.

### Roles

- **Depositor**
- **Vault contract**
- **Yield strategy**

### Security goals (formulate each as a theorem/lemma)

| # | Goal name | Property |
|---|-----------|----------|
| 1 | `share_price_monotonicity` | Existing depositors' redeemable assets never decrease due to another user's deposit/redeem. |
| 2 | `no_inflation_theft` | An attacker cannot profit by donating assets and exploiting rounding on the first/last deposit. |

### Threat model

Adversary is an ordinary depositor who can choose deposit amounts and donate tokens directly to the vault.

### What to decide

Whether the goals hold for the deployed protocol as described. If a goal
fails, produce a concrete sequence of on-chain transactions/messages (an
attack trace) and the resulting violation. If you can, back it with a
machine-checked proof in your chosen tool.

### References

- https://eips.ethereum.org/EIPS/eip-4626
- https://docs.openzeppelin.com/contracts/4.x/erc4626
