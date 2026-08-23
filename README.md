# omo-validator

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
| Validation Registry interface | `contracts/IValidationRegistry.sol` | written from public spec — confirm against deployed ABI before use |
| Seal/reveal adapter | `contracts/OmoValidationAdapter.sol` | holds no funds, operator-key gated, mirrors omo's commit-key separation |
| Commit/reveal/verify API | `src/main.py` | FastAPI skeleton, on-chain calls stubbed pending RPC + deployed adapter address |

## not yet done (in order)

1. Confirm the actual deployed `IValidationRegistry` ABI on Robinhood Chain
   (or wherever ERC-8004 registries are live) — the interface here is
   written from the EIP text, not a copied ABI.
2. Deploy `OmoValidationAdapter` pointed at that registry.
3. Wire `_seal_on_chain` / `_reveal_on_chain` in `src/main.py` to web3.py
   against the adapter address.
4. Persistence: swap the in-memory dict for Supabase, matching your usual stack.
5. Backtest harness for the *gate rules themselves* (separate from this
   attestation layer) against historical price data before anyone wires up
   a live trading key on top of this.

## explicitly out of scope

No trading key, no held funds, no directional position. This service only
ever proves that a decision preceded an action — same boundary omo draws
between its commit-only burner key and its trading key.
