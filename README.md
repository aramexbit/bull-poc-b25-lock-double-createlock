# PoC for Bull.family bug bounty report B-25

## SDK `lock()`: never counts steps or totals — malicious server duplicates createLock and the victim locks twice the amount they asked for

**Report B-25** (K-711). SDK under test: `sdk-live.mjs` — the Bull SDK live
19 Nov 2026, sha256 `3c1319e1…`, 34,788 bytes
(`https://www.bull.family/sdk/bull.mjs`).

### The bug

The SDK states: *"Safety: the API server is not trusted with your wallet.
Every transaction it returns is checked before it is sent."* `agree()` and
`deal()` in the same file count the steps they receive — `agree()` refuses
unless exactly one `createAgreement` step is returned (`creates !== 1` →
throw). `lock()` does no counting at all. Its loop sends every step the
server returns with `#send(tx, 0n, { locker, fn: [], maxApprove })`, and its
post-transaction check reads only ONE `LockCreated` event (from the last
receipt) and compares token/beneficiary/amount against the request. A
duplicated `createLock` step has the same token, the same beneficiary, and
the same amount — so it passes every check `lock()` has.

The attack needs a compromised/malicious API server (the SDK's own
documented threat model). The victim calls `lock()` for 500 tokens; the
server returns `approve + createLock` TWICE; `lock()` returns the lock id
with NO error. The victim asked to lock 500 and locked 1,000. In the
immediate-vesting variant the first lock is fully vested at creation, so
the beneficiary claims the extra 500 at once.

**Measured (fresh Anvil):** P1 — victim −1,000 (asked 500), locks 0→2;
P2 — employee claimed +500 at once; C0 (honest lock) — victim −500
exactly, claimable 0. 500 tokens per duplication, uncapped in general.

### Why this is not a duplicate

**B-14** (report `363f96aae6`) was the server PREPENDING a `createAgreement`
step — a function that does not belong in the lock flow — admitted because
`lock()` passed no `fn`/`id`/`check` to the guard. That mechanism is now
DEAD: the patch gives `lock()` `fn: []`, and the round-12 recheck proves a
prepended `createAgreement` is refused. K-711 duplicates the ALLOWED
function (`createLock` itself); the B-14 fix (a function allowlist) cannot
close it. Different mechanism, different fix (count steps + totals, as
`deal()` does). Dedupe risk, stated honestly: MEDIUM.

This is also not B-17 (`deal()` sum — a different function), B-13 (the
vesting schedule), or B-18 (the beneficiary).

### How to reproduce

Local Anvil chain 4663, mock Bull API, real SDK verbatim, mock locker — no
real funds, no mainnet, no Bull infrastructure. All keys are Anvil's public
throwaway test keys.

1. Start Anvil: `anvil --port 8547 --chain-id 4663`
2. In this directory: `npm install`, then `node run-poc.mjs` (cases "K-711
   P1" and "K-711 P2"; the same runner also covers K-735 P3 and the K-712
   trailing-data note, with control C0)

Forge tests (mock locker): `cd chain && forge test` — 11/11 green.

`poc-result.json` holds the measured results (`exploited: true` for K-711
P1/P2).

### Suggested fix

In `lock()`, count the `createLock` steps the server returns — exactly one,
like `agree()` counts `createAgreement` steps (`creates !== 1` → throw) —
and verify the SUM of the locked amounts equals the amount requested.
