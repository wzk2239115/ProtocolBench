# Protocol modeling task

Model the protocol described below and analyze it. The agent is free to choose
its method (Lean, Tamarin, Verifpal, or a combination). Deliverables follow the
task README (`verdict.json`, `attack_report.md` when a goal fails, and the
formal evidence in your chosen tool).

The security goals you formulate should cover, at minimum: message authenticity,
no replay, and value conservation.

---

## Protocol: lock-and-mint cross-chain bridge (Nomad-style optimistic bridge)

**Source:** Nomad token bridge (deployed 2022; exploited for ~US$190M on
2022-08-01). Modeled after the fork of the `optics`/Nomad `Replica` contract.

### Overview

A bridge moves tokens between a **home chain** and a **remote chain**.

- On the home chain, a user **locks** tokens in the bridge contract and emits a
  `Message` describing the transfer: `(destination_chain, recipient, amount,
  message_id)`. Every emitted message is inserted into a Merkle tree; the tree
  root is called a **committed root**.
- A set of **validators** (watchers) observe committed roots and sign
  attestations. A root that has gathered signatures from the validator quorum
  is **confirmed** and is stored in the contract's `acceptableRoot` mapping
  (`acceptableRoot[root] = true`).
- On the remote chain, anyone may call `process(message, merkleProof, root)`.
  The contract:
  1. checks `acceptableRoot[root]` is true;
  2. verifies `merkleProof` that `message` is a leaf of the tree with root
     `root`;
  3. executes the mint: `balance[recipient] += amount`.

### Deployment detail relevant to the model

The remote contract is initialised with `acceptableRoot[0] = true`, i.e. the
**zero root is acceptable from genesis**. This was done so the bridge can
bootstrap before the first validator attestation. The contract does not
distinguish "root confirmed by a validator quorum" from "root present in the
mapping"; both are treated identically by `process`.

### Roles

- **User (depositor)** — locks tokens on the home chain.
- **Validators** — attest to committed roots on the remote chain.
- **Relayer / anyone (adversary)** — calls `process` on the remote chain.

### Security goals (formulate each as a theorem/lemma)

| # | Goal name | Property |
|---|-----------|----------|
| 1 | `only_confirmed_messages` | A message can be processed on the remote chain only if its root was confirmed by a validator quorum. |
| 2 | `no_replay` | Each `(message_id, destination_chain)` pair is processed at most once. |
| 3 | `value_conservation` | The total minted amount on the remote chain never exceeds the total locked amount on the home chain. |

### Threat model

- The adversary is an unprivileged user of the remote chain: it can read all
  on-chain data, submit any transaction, and choose its payload, but it does
  not control the validators and cannot forge their signatures.
- The validator set is honest and eventually confirms every honestly committed
  root.

### What to decide

Whether goals 1–3 hold for the deployed contract behaviour above. If a goal
fails, produce a concrete sequence of transactions (an attack trace) and show
the forged mint that violates it.

### References

- Nomad bridge incident (2022-08-01): the acceptable-root mapping accepted the
  zero root, so arbitrary messages could be proven against it and minted.
- Bitcoin Cross-Chain Bridge taxonomy (arXiv 2509.10413): Lock-Mint /
  Burn-Mint bridge models.
- Survey on Cross-chain Technologies (ACM CSUR 2023, 10.1145/3573896).
