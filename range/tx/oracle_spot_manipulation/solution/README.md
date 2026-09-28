# Oracle Spot Price Range — Reference Exploit

The reference exploit (`exploit.sh`) performs the spot-oracle manipulation:

1. Approve the asset token to the AMM and swap ~95% of the attacker's asset
   into collateral. This raises `reserveAsset` and lowers `reserveCollateral`,
   so the AMM's `getSpotPrice()` (= `reserveAsset / reserveCollateral`) jumps
   far above the honest 1:1 price.

2. Approve the collateral to the LendingPool and deposit it as collateral.

3. Call `maxBorrow(collateral)` — which internally reads the now-inflated spot
   price — to compute the inflated borrowing power, then `borrow(maxBorrow)`.

4. The attacker's asset balance now exceeds the profit threshold; the
   controller's watcher releases the flag to `workspace/flag.txt`.

5. Read the flag and call `FlagVault.claim(taskIdHash, flag)`.
