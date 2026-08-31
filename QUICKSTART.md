# Quickstart: integrating with Provenar

This is for you if you're building an agent and want provable evidence
that your agent's decisions preceded its actions — without trusting a
database you don't control.

Provenar is a **Validation Registry provider** for [ERC-8004](https://github.com/erc-8004/erc-8004-contracts)
on Robinhood Chain testnet. It doesn't hold your funds or your agent's
keys. It only does one thing: seals a hash of your agent's decision
*before* the agent acts, then — once you've told the standard registry
to expect a response from Provenar — publishes a score for that decision
that anyone can independently verify on-chain.

## The mental model

1. Your agent decides something (a trade, a recommendation, whatever).
2. Before acting on it, your agent calls Provenar's `POST /commit` with
   that decision. Provenar hashes it and seals the hash on-chain. Your
   agent gets back a `request_id` and `request_hash`.
3. Your agent calls `validationRequest()` on the real ERC-8004
   ValidationRegistry, naming Provenar's adapter contract as the
   validator for that `request_hash`. (This step happens on-chain,
   directly from your agent's own wallet — Provenar never does this
   for you, by design: it proves *you* asked for validation, not that
   Provenar made it up.)
4. Your agent acts on the decision.
5. Your agent calls Provenar's `POST /reveal` with the outcome and a
   score (0–100). Provenar checks the revealed decision actually
   matches what was sealed, then publishes the score on-chain via the
   real registry's `validationResponse()`.
6. Anyone — you, a marketplace, another agent — can now read that score
   directly from the ValidationRegistry contract. Not from Provenar's
   database. From the public chain.

## What you need before starting

- An EVM wallet with a small amount of Robinhood Chain testnet ETH.
  Get some free from the official faucet:
  **https://faucet.testnet.chain.robinhood.com**
  (ignore any other "robinhood faucet" site — several clones exist)
- Python 3.12+ if you want to use the reference client below, or just
  any HTTP client if you're calling the API directly from your own stack.

## Deployed contracts (Robinhood Chain testnet, chain ID 46630)

| Contract | Address |
|---|---|
| IdentityRegistry | `0xa44f32c6ac995e747f98cdb8a4d822b04af6decd` |
| ValidationRegistry | `0xb765bc96851378c893988e45e5d29fd224fdad7d` |
| Provenar's adapter (validator) | `0x2625b77F4cc01208201D85E0914DFAc18852891a` |

## Provenar's API

Base URL: `https://ominous-sniffle-p7rq9pjwvjqwcxp9-8000.app.github.dev`

**Note:** this is a Codespaces-forwarded port, not a durable production
deployment. It only responds while the maintainer's Codespace is running
and its port is set to public visibility. If you get connection errors,
it may simply be offline right now — check back, or ask.

Interactive docs (try requests directly in the browser):
`https://ominous-sniffle-p7rq9pjwvjqwcxp9-8000.app.github.dev/docs`

### `POST /commit`
```json
{
  "agent_id": 1,
  "decision": { "your": "decision payload, any JSON shape" }
}
```
Returns:
```json
{
  "request_id": "abc123",
  "request_hash": "...",
  "sealed_at": 1234567890
}
```
Your `agent_id` must be a real ERC-8004 identity you registered by
calling `register()` on the IdentityRegistry above — you own it, so
you're allowed to name Provenar as your validator later.

### Your agent then calls, on-chain, itself:
```
ValidationRegistry.validationRequest(
  validatorAddress: 0x2625b77F4cc01208201D85E0914DFAc18852891a,
  agentId: <your agentId>,
  requestURI: "<anything, or empty string>",
  requestHash: <the request_hash from /commit, as bytes32>
)
```

### `POST /reveal`
```json
{
  "request_id": "abc123",
  "decision": { "the exact same payload you sent to /commit" },
  "score": 87,
  "evidence_uri": "https://wherever-your-outcome-record-lives.com",
  "tag": "whatever short label you want"
}
```
This will fail with a 400 if `decision` doesn't exactly match what you
committed — that's the point. It will fail on-chain if you skipped the
`validationRequest()` step above.

### `GET /verify/{request_id}`
Read back the full record and a set of pass/fail checks, independent of
whether you trust Provenar's own claims.

## A working reference implementation

See `toy_agent.py` in this repo — it's a complete, minimal script that
does all six steps above for real, against the real testnet contracts.
Read it before writing your own integration; it's short and has no
hidden magic.

## If something doesn't work

This is genuinely new — you may hit rough edges. Please say exactly
what you tried, what you expected, and what happened instead. That's
more useful than "it doesn't work."
