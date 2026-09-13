# Protocol modeling task

Model the protocol described below and analyze it. The agent is free to choose
its method (Lean, Tamarin, Verifpal, or a combination). Deliverables follow the
task README (`verdict.json`, `attack_report.md` when a goal fails, and the
formal evidence in your chosen tool).

The security goals you formulate should cover, at minimum: allowance upper
bound, approval atomicity, and no unauthorized transfer.

---

## Protocol: ERC-20 token allowance workflow

**Source:** EIP-20 token standard (https://eips.ethereum.org/EIPS/eip-20),
section "Security Considerations".

### Overview

ERC-20 is the dominant fungible-token interface on Ethereum. A token contract
maintains a balance for every account and an *allowance* — a per-(owner,
spender) amount that the owner lets the spender transfer on the owner's behalf.
Two state-changing operations matter here:

- `approve(spender, value)` — called by the owner; sets
  `allowance[owner][spender] := value`.
- `transferFrom(from, to, value)` — called by the spender; requires
  `allowance[from][spender] >= value` and `balance[from] >= value`; then
  `balance[from] -= value`, `balance[to] += value`. The allowance is **not**
  decremented.

Each operation is a separate transaction, mined independently. Transactions
are ordered by the block producer (adversary). A pending transaction sits in
the mempool until included, and the adversary can choose the inclusion order
of any set of pending transactions.

### Roles

- **Owner (Alice)** — the token holder granting the allowance.
- **Spender (Bob)** — an untrusted party authorised to move Alice's tokens.
- **Block producer (adversary)** — chooses transaction ordering and inclusion.

### Behaviour

1. Alice submits `approve(Bob, N)`.
2. Alice later decides to lower Bob's allowance to `M`, where `M < N`, so she
   submits `approve(Bob, M)`.
3. Bob has pending `transferFrom(Alice, Bob, v)` calls and the adversary can
   place them anywhere relative to Alice's two approvals.

### Security goals (formulate each as a theorem/lemma)

| # | Goal name | Property |
|---|-----------|----------|
| 1 | `allowance_upper_bound` | At any point, the total amount Bob has received via `transferFrom` from Alice never exceeds the maximum amount Alice has authorised so far. |
| 2 | `approval_atomicity` | After Alice's second approval is mined, Bob cannot transfer more than `M` in total from that point, regardless of what he did before. |
| 3 | `no_unauthorized_transfer` | Bob cannot transfer more than the current allowance. |

### Threat model

- The adversary controls transaction ordering/inclusion but cannot forge
  Alice's approvals or change her balance.
- Alice's approvals are honest and are both eventually mined.

### What to decide

Whether goals 1–3 hold for the ERC-20 allowance workflow above. If a goal
fails, produce a concrete transaction ordering (an attack trace) and the
resulting asset transfer that violates it.

### References

- EIP-20: Token Standard — https://eips.ethereum.org/EIPS/eip-20
- EIP-20 security considerations explicitly note that `approve` can be used
  for both setting and changing an allowance and warn about the resulting
  ordering hazard.
