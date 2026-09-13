# Protocol modeling task

Model the protocol described below and analyze it. You may use any method
(Lean 4, Tamarin, Verifpal, or a combination of them). Deliverables follow the
task README: `verdict.json`, an attack report when a goal fails, and
machine-checkable evidence in your chosen tool.

**No model is provided.** You decide the strategy: formalize the whole protocol
first, or reason about the likely flaw and then prove it. The security goals you
must formulate should cover, at minimum: repayment_atomicity, no_balance_manipulation, initiator_binding.

---

## Protocol: ERC-3156 Flash Loans

**Category:** defi

### Overview

ERC-3156 standardizes flash loans: a lender transfers assets to a borrower, calls onFlashLoan, and requires repayment plus fee before the transaction ends.

### Roles

- **Lender**
- **Borrower**
- **Receiver**

### Security goals (formulate each as a theorem/lemma)

| # | Goal name | Property |
|---|-----------|----------|
| 1 | `repayment_atomicity` | The transaction reverts unless principal plus fee is repaid. |
| 2 | `no_balance_manipulation` | A flash loan cannot leave the lender with fewer assets. |
| 3 | `initiator_binding` | The callback verifies the caller is the trusted lender. |

### Threat model

Adversary is a borrower with arbitrary callback code and atomic composability.

### What to decide

Whether the goals hold for the deployed protocol as described. If a goal
fails, produce a concrete sequence of on-chain transactions/messages (an
attack trace) and the resulting violation. If you can, back it with a
machine-checked proof in your chosen tool.

### References

- https://eips.ethereum.org/EIPS/eip-3156
