# Reference: ERC-721A (batch minting)

**Verdict: UNSAFE.**

The packed ownership-slot optimization has had edge-case bugs around burning and transferring the first token owned by an address, where a naive implementation can report wrong ownership; these require very careful slot bookkeeping.

## References

- https://www.erc721a.org/
- ERC-721A reference implementation
