# Reference: Axelar General Message Passing

**Verdict: UNSAFE.**

Security reduces to the Axelar validator set (permissioned-ish) and the gateway's command handling; historical cross-chain gateway implementations have suffered command-id replay and approval-amount encoding bugs, and a validator-set failure is catastrophic.

## References

- https://docs.axelar.dev/
