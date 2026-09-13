# Reference: ERC-20 allowance race

**Verdict: UNSAFE.** Documented in EIP-20's security considerations; a
well-known interface-level hazard.

## Attack

Alice holds 1000 tokens and wants to authorise Bob up to 100, then reduce the
authorisation to 50. She submits:

1. `approve(Bob, 100)`
2. `approve(Bob, 50)`

The adversary (block producer) orders the mempool as:

1. `approve(Bob, 100)` — allowance = 100
2. `transferFrom(Alice, Bob, 100)` — Bob receives 100; allowance stays 100
3. `approve(Bob, 50)` — allowance = 50
4. `transferFrom(Alice, Bob, 50)` — Bob receives 50 more; allowance stays 50

Bob ends with 150 tokens although Alice never intended to authorise more than
100 (and after step 3, believed the cap was 50).

## Root cause

`approve` is not atomic with respect to a spender's `transferFrom`, and
`transferFrom` does not decrement the allowance. During the window between the
two approvals the spender may consume the old (higher) allowance, then consume
the new allowance as well. The pattern is safe only if the owner first sets the
allowance to 0 (or uses `increaseAllowance`/`decreaseAllowance`), which the
standard does not require.

## Fix

- Require the owner to zero the allowance before setting a new value, or
- use `increaseAllowance`/`decreaseAllowance`, or
- decrement the allowance in `transferFrom` (non-standard).
