# Reference: Multichain anyCall (router)

**Verdict: UNSAFE.**

The July 2023 drain was enabled by workflow/processing issues around the token router and the custodian-held MPC keys (multiple incidents of the same class). Messages passed the check but accounting did not bind the locked amount to the minted amount.

## References

- Multichain 2023 incident (~US$126M)
