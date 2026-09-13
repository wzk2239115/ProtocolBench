# Reference: RISC Zero zkVM

**Verdict: UNSAFE.**

The proof system is sound, but dApps must bind the image id and journal to the intended context: accepting a receipt without checking the image id, or reusing a journal across different contracts, lets an attacker replay a valid receipt for an unrelated action.

## References

- https://dev.risczero.com/
- RISC Zero docs
