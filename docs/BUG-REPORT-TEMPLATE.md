# SwitchBitcoin pre-alpha — bug report

Copy this file, fill every section, send it through your onboarding channel.
One report per problem. SAFETY: never include your mnemonic, passphrase, or
RPC password — `diag` output is safe by construction; terminal scrollback
from `init` is NOT (it showed the mnemonic once).

## What happened (one sentence)

## Exact steps to reproduce
1.
2.
3.

## Expected vs actual
- expected:
- actual:

## `switchbitcoin-cli diag` output (paste the whole block)
```
(run: switchbitcoin-cli diag)
```

## The failing command + its FULL stderr
```
(re-run the failing command and paste everything it printed)
```

## Environment
- Bitcoin Core version (`bitcoind --version` first line):
- network (testnet4 / regtest):
- OS:
- if swapping: was your partner on the same build? (`switchbitcoin-cli version` both sides)

## Severity (your call)
- [ ] funds appear stuck or lost (report IMMEDIATELY, keep the wallet running)
- [ ] a swap failed in a way the guide's troubleshooting table doesn't explain
- [ ] wrong/confusing output, docs, or UX
- [ ] other

## Anything else (timing, mempool conditions, `status` before/after, ...)
