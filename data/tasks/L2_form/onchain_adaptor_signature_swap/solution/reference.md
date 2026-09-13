# Reference: Scriptless Atomic Swap (adaptor signatures)

**Verdict: UNSAFE.**

Adaptor-signature atomic swaps do not rely on timeouts for fairness: the witness is cryptographically bound, so settling one leg enables the other. Safe under the underlying signature assumptions.

## References

- https://github.com/ElementsProject/scriptless-scripts
- Adaptor signature literature
