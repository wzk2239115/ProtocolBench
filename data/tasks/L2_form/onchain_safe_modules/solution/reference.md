# Reference: Gnosis Safe Modules and Guards

**Verdict: UNSAFE.**

Enabled modules have full execution power over the Safe; a malicious or buggy module (or one enabled through a single compromised owner signature) drains all assets, bypassing the threshold. Real Safe deployments have been drained via malicious modules and via delegatecall to untrusted contracts.

## References

- https://docs.safe.global/advanced/smart-account-modules
- Safe modules/guards
