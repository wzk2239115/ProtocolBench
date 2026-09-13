# Protocol modeling task

Model the protocol described below and analyze it. The agent is free to choose
its method (Lean, Tamarin, Verifpal, or a combination). Deliverables follow the
task README (`verdict.json`, `attack_report.md` when a goal fails, and the
formal evidence in your chosen tool).

The security goals you formulate should cover, at minimum: replay resistance
and single-use of signed transactions.

---

## Protocol: signed-transaction broadcast over a split chain

**Source:** Ethereum / Ethereum Classic account model; the replay-protection
failure at the 2016 DAO hard fork that motivated EIP-155
(https://eips.ethereum.org/EIPS/eip-155).

### Overview

A user account is controlled by a private key. To move funds the user signs a
transaction `tx = (to, value, nonce, gasPrice, gasLimit)` with their private
key and broadcasts the signed transaction to the network. Miners include it in
a block; the account's balance and nonce are updated.

The signed payload covered by an **unprotected** (pre-EIP-155) signature is:

    encode(rlp([nonce, gasPrice, gasLimit, to, value, data]))

It does **not** include any network/chain identifier. At a chain split, two
chains share the same account state (same balances, same nonces) and the same
signature-verification rules.

### Roles

- **Signer (victim)** — owns the account; signs and broadcasts one transaction.
- **Network(s)** — two chains with an identical genesis/account state.
- **Adversary** — observes the broadcast signed transaction on one chain and
  may submit it to any chain.

### Behaviour

1. The signer signs `tx` and broadcasts it to chain A.
2. Chain A includes `tx`, debiting the signer's account.
3. The adversary copies the very same signed `tx` (identical bytes) and submits
   it to chain B.

Because both chains have the same account state and the transaction does not
commit to a chain id, chain B accepts the same signature and debits the
signer's account again.

### Security goals (formulate each as a theorem/lemma)

| # | Goal name | Property |
|---|-----------|----------|
| 1 | `no_cross_chain_replay` | A transaction signed for one chain is never accepted by a different chain. |
| 2 | `single_use` | A given signed transaction is applied at most once across the whole network. |
| 3 | `nonce_monotonicity` | For each account, the applied nonce increases by exactly one per accepted transaction on each chain. |

### Threat model

- The adversary can read all broadcast transactions and submit arbitrary
  well-formed signed transactions to either chain.
- The adversary does not know the signer's private key and cannot forge new
  signatures.
- Both chains are honest (they faithfully apply their own verification rules).

### What to decide

Whether goals 1–3 hold for the unprotected signature scheme above. If a goal
fails, produce a concrete sequence of signed transactions and chain inclusions
(an attack trace) that violates it.

### References

- EIP-155: Simple replay attack protection —
  https://eips.ethereum.org/EIPS/eip-155
- 2016 DAO hard fork / ETH-ETC split: unprotected transactions were replayed
  across the two chains until replay protection (chain id in the signed
  payload) was adopted.
