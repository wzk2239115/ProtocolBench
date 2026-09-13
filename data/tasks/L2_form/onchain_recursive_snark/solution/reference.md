# Reference: Recursive SNARK / proof aggregation

**Verdict: UNSAFE.**

Incorrectly embedding the inner verification key, public inputs, or domain separator in the recursive circuit lets a prover fork/replay proofs across contexts; recursive-circuit bugs are a documented source of counterfeiting (e.g. the Zcash Orchard incident).

## References

- Recursive SNARK literature
- Halo/Nova/Pickles
