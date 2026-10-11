# contracts — reconstructed Papertrade contracts

Reverse-engineered from Heimdall decompile + live `eth_call` traces.
Ground truth = 4-byte selectors (all verified against bytecode).

| File | Source | Status |
|---|---|---|
| `src/IExchange.sol` | Heimdall ABI (160 entries) | exact interface, all selectors match |
| `src/PriceOracle.sol` | verified behavior (BBO 0x080e, mid, no TWAP) | compiles, logic faithful |
| `src/UserWallet.sol` | wallet logic 0xe0bc (permissions, allowlist, 0x251fb27d) | compiles; sig preimage marked HYPOTHESIS |
| `src/PaperToken.sol` | PAPER impl (ERC20 + gated mint) | compiles, mint gate verified live |

Exchange implementation is intentionally interface-only: 23KB/168 selectors
need trace-driven reconstruction per function — tracked as follow-up.
Do NOT deploy against mainnet without re-verifying codehashes (all proxies upgradeable).
