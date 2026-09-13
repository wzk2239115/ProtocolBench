# Reference: Parity Multisig Wallet (2017)

**Verdict: UNSAFE.**

Two flaws: (1) July 2017 - the library's initWallet/execute were callable by anyone because the wallet proxy delegated to the uninitialized library, letting attackers re-initialize wallets and drain funds; (2) November 2017 - an attacker became the owner of the library contract itself, called kill(), and permanently froze all dependent wallets (~US$150M). Missing initialization guard and missing access control on the library.

## References

- Parity multisig incidents (July and November 2017)
