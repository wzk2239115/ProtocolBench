# Protocol modeling task

Model the protocol described below and analyze it. You may use any method
(Lean 4, Tamarin, Verifpal, or a combination of them). Deliverables follow the
task README: `verdict.json`, an attack report when a goal fails, and
machine-checkable evidence in your chosen tool.

**No model is provided.** You decide the strategy: formalize the whole protocol
first, or reason about the likely flaw and then prove it. The security goals you
must formulate should cover, at minimum: one_to_one_backing, no_double_withdraw.

---

## Protocol: Wrapped Ether (WETH)

**Category:** token

### Overview

WETH escrows ETH 1:1 and issues an ERC-20 balance: deposit() is payable and mints WETH, withdraw(amount) burns WETH and sends ETH.

### Roles

- **User**
- **WETH contract**

### Security goals (formulate each as a theorem/lemma)

| # | Goal name | Property |
|---|-----------|----------|
| 1 | `one_to_one_backing` | The contract's ETH balance always equals the total WETH supply. |
| 2 | `no_double_withdraw` | Each WETH unit can be withdrawn at most once. |

### Threat model

Adversary can call deposit/withdraw with arbitrary amounts, including from contracts.

### What to decide

Whether the goals hold for the deployed protocol as described. If a goal
fails, produce a concrete sequence of on-chain transactions/messages (an
attack trace) and the resulting violation. If you can, back it with a
machine-checked proof in your chosen tool.

### References

- https://weth.io/
- WETH9 reference implementation
