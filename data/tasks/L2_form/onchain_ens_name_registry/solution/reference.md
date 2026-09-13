# Reference: ENS Name Registry

**Verdict: UNSAFE.**

The commit-reveal scheme has historically been bypassed/raced (commitments are only weakly bound to the registrant, and reveal front-running/griefing is possible); name-wrapper and resolver-controller permissions have allowed unauthorized record changes and takeover in misconfigured setups.

## References

- https://docs.ens.domains/
- ENS registry/registrar
