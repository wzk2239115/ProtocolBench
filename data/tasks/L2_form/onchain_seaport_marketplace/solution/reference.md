# Reference: OpenSea Seaport

**Verdict: UNSAFE.**

Order matching is extremely expressive; signature-domain confusion (e.g. counter/maker signature validity), mismatched offer/consideration tips, and unlisted consideration recipients have enabled thefts and trick users into signing orders that transfer more than expected. Social-engineering/order-hash confusion is the dominant real loss.

## References

- https://github.com/ProjectOpenSea/seaport
- Seaport documentation
