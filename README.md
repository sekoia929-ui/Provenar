# Provenar

A commit-as-a-service **ERC-8004 Validation Registry provider**.

Any AI agent (yours or a third party's) can seal a decision before acting on
it, then reveal the outcome afterward — and this service publishes the
pass/fail result to the standard ERC-8004 Validation Registry, not a
bespoke endpoint. Other agents or marketplaces already querying the
registry get real, cryptographically-checkable evidence instead of the
Sybil-able reputation scores the ecosystem is currently stuck with.

## why

- ERC-8004's Reputation Registry is empirically broken: most registrations
  are placeholders, and the majority of feedback on live chains shows
  coordinated Sybil behavior (see `docs/erc8004-notes.md` — TODO).
- The Validation Registry is the intentionally-unopinionated slot for real
  verification logic. Nobody has filled it with a precommit/reveal proof
  pattern yet.
- omo (github.com/sekoia929-ui/omo) already validated this exact pattern
  on Solana for its own trading loop. This project generalizes it as
  infrastructure other agents can use, on an EVM chain (Robinhood Chain /
  any Arbitrum Orbit chain) where ERC-8004 is natively supported.

## pieces

| piece | file | status |
| --- | --- | --- |
| Validation Registry interface | `contracts/IValidationRegistry.sol` | corrected against the real deployed ABI (erc-8004/erc-8004-contracts), not just the EIP text |
| Seal/reveal adapter | `contracts/OmoValidationAdapter.sol` | holds no funds, operator-key gated, mirrors omo's commit-key separation — **deployed on Robinhood Chain testnet**, see below |
| Commit/reveal/verify API | `src/main.py` | FastAPI, wired to real web3.py calls — verified end-to-end against a local chain, see "Verification" below |

## deployed addresses (Robinhood Chain testnet, chain ID 46630)

| contract | address |
| --- | --- |
| IdentityRegistry (proxy) | `0xa44f32c6ac995e747f98cdb8a4d822b04af6decd` |
| ValidationRegistry (proxy) | `0xb765bc96851378c893988e45e5d29fd224fdad7d` |
| OmoValidationAdapter | `0x2625b77F4cc01208201D85E0914DFAc18852891a` |

Deployed via `lib/erc-8004-contracts/scripts/deploy-provenar.ts` (registries)
and `script/Deploy.s.sol` (adapter). The default `ignition/modules/ERC8004.ts`
in the vendored submodule is stale — it references pre-upgrade contract
names that no longer exist — so registries were deployed with a custom
script using the tested `HardhatMinimalUUPS` → upgrade pattern from
`test/upgradeable.ts` instead.

## persistence

State lives in Supabase Postgres (project `provenar`, table `commitments`),
not an in-memory dict — survives server restarts. RLS is locked to "no
public access"; the backend uses the `service_role` key, which bypasses
RLS by design (this backend is the only trusted writer/reader of this
table).

Env vars needed in addition to the chain ones below:

```bash
export SUPABASE_URL=https://pbbxcxbyimagfyzotyen.supabase.co
export SUPABASE_SERVICE_KEY=<service_role key -- get from Supabase dashboard:
  Project Settings -> API -> Project API keys -> service_role (click to reveal)>
```

The `service_role` key is NOT available via the Supabase MCP connector on
purpose (it only exposes publishable/anon keys) -- grab it from the
dashboard directly, and treat it like any other credential that grants
full write access: don't commit it, don't paste it in chat.

## running the API against a deployed adapter

```bash
pip install -r requirements.txt
export ROBINHOOD_RPC_URL=https://rpc.testnet.chain.robinhood.com
export ADAPTER_ADDRESS=0x2625b77F4cc01208201D85E0914DFAc18852891a
export ADAPTER_OPERATOR_PRIVATE_KEY=<the wallet that deployed the adapter>
uvicorn src.main:app --reload
```

Without these three env vars set, `/commit` and `/reveal` still work but
return `"unarmed"` instead of a real tx hash — same convention as omo:
gates and gets the plaintext right locally, just doesn't touch the chain.

## verification

Both the Foundry contract tests (`forge test`, 7/7 passing) and a full
local end-to-end run (Anvil + real `seal()`/`reveal()` transactions +
an independent `cast call getValidationStatus(...)` read, bypassing this
service's own API entirely) confirm the whole loop: commit hashes and
seals → an agent calls `validationRequest()` naming this adapter as
validator → reveal checks the plaintext matches, then calls
`validationResponse()` → the score lands on-chain and reads back correctly
from the registry directly.

## not yet done (in order)

1. Get one real third-party agent through the full loop on the actual
   Robinhood Chain testnet deployment above -- `toy_agent.py` proved the
   loop works with an agent I wrote myself; the next test is someone
   else's agent, with no inside knowledge of how Provenar is built.
2. Backtest harness for the *gate rules themselves* (separate from this
   attestation layer) against historical price data before anyone wires up
   a live trading key on top of this.
3. Metered-tier billing logic (free tier / per-commitment pricing) once
   there's real usage to meter.

## explicitly out of scope

No trading key, no held funds, no directional position. This service only
ever proves that a decision preceded an action — same boundary omo draws
between its commit-only burner key and its trading key.
