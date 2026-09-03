| name        | provenar-precommit                                                                                                          |
| ----------- | ---------------------------------------------------------------------------------------------------------------------------- |
| description | Precommit/reveal proof for ERC-8004 agents. Seals a decision hash on-chain before an agent acts, publishes a verifiable score after. Testnet only. No API key needed. |
| version     | 0.1.0                                                                                                                       |
| tags        | erc-8004, validation, precommit, trust, agents, robinhood-chain                                                             |
| metadata    | homepage: https://provenar.onrender.com — requires: curl                                                                    |

# Provenar — Precommit/Reveal Proof for ERC-8004 Agents

Most agent trust tools (like TrustLayer's Sybil scanner) tell you whether
an agent's *reputation* looks real, based on past reviews. Provenar
answers a different, narrower question: **did this specific decision
actually happen the way the agent now claims it did?**

An agent seals a hash of its decision *before* acting. Later it reveals
the plaintext and gets a score, published to the standard ERC-8004
Validation Registry — not a database you have to trust, a public
on-chain record anyone can independently re-check.

These two tools are complementary, not competing: TrustLayer for "is
this agent generally trustworthy," Provenar for "did this one decision
match what was committed to beforehand."

**API Base:** `https://provenar.onrender.com`
**No API key required.** Rate-limited instead: 10 commits/hour, 20
reveals/hour per IP, to prevent spam without gating out real agents.
**Robinhood Chain testnet only right now** — this is early, working
infrastructure, not a production mainnet service yet.

## What this catches that reputation scores can't

- **Post-hoc rationalization**: an agent that only decides *after* the
  outcome is known, then claims it planned that all along. Sealing the
  hash before acting makes this structurally impossible to fake.
- **Silent editing**: revealing a different decision than what was
  actually sealed. The reveal step recomputes the hash and rejects any
  mismatch before anything reaches the chain.
- **Unfalsifiable claims**: an agent simply asserting "I was right"
  with nothing to check it against. Every score here traces back to a
  public transaction anyone can open in a block explorer.

## When to use this skill

- Before trusting a specific claimed decision from an agent, not just
  its general reputation
- When building an agent yourself and you want a way to prove your own
  decisions weren't made up after the fact
- When evaluating whether an agent's trading/recommendation logic is
  honest, not just whether its reviews look good

## Seal a decision (before acting)

```
curl -s -X POST https://provenar.onrender.com/commit \
  -H "Content-Type: application/json" \
  -d '{"agent_id": <your ERC-8004 agentId>, "decision": {<any JSON>}}'
```

Returns a `request_id` and `request_hash`. The hash is published
on-chain immediately — this is the "precommit."

Your `agent_id` must be a real identity you registered by calling
`register()` on the IdentityRegistry (see contract addresses below) --
you own it, so you're allowed to name Provenar as your validator next.

## Name Provenar as your validator (on-chain, from your own wallet)

```
cast send <ValidationRegistry address> \
  "validationRequest(address,uint256,string,bytes32)" \
  <Provenar adapter address> <your agentId> "<any URI>" <request_hash> \
  --rpc-url https://rpc.testnet.chain.robinhood.com --private-key $YOUR_KEY
```

This step happens directly from your wallet, not through Provenar --
that's what makes the later score meaningful: Provenar can't fake
having been asked to validate you.

## Reveal the outcome (after acting)

```
curl -s -X POST https://provenar.onrender.com/reveal \
  -H "Content-Type: application/json" \
  -d '{"request_id": "<from /commit>", "decision": {<the exact same JSON>}, "score": <0-100>, "evidence_uri": "<where the outcome record lives>", "tag": "<short label>"}'
```

Fails with 400 if `decision` doesn't exactly match what was sealed --
that's the point. Fails on-chain if the `validationRequest` step above
was skipped.

## Check any result, independent of Provenar's own claims

```
curl -s https://provenar.onrender.com/verify/<request_id>
```

Or view it rendered: `https://provenar.onrender.com/v/<request_id>`

Or read directly from the registry, bypassing Provenar's API entirely:

```
cast call <ValidationRegistry address> \
  "getValidationStatus(bytes32)(address,uint256,uint8,bytes32,string,uint256)" \
  <request_hash> --rpc-url https://rpc.testnet.chain.robinhood.com
```

## Deployed contracts (Robinhood Chain testnet, chain ID 46630)

| Contract | Address |
| --- | --- |
| IdentityRegistry | `0xa44f32c6ac995e747f98cdb8a4d822b04af6decd` |
| ValidationRegistry | `0xb765bc96851378c893988e45e5d29fd224fdad7d` |
| Provenar's adapter (validator) | `0x2625b77F4cc01208201D85E0914DFAc18852891a` |

## Live dashboard

`https://provenar.onrender.com` — every commitment made so far, real
data, no fabrication. Free-tier hosting: may take 30-60 seconds to wake
up if it's been idle.

## Full docs and working reference agents

`https://github.com/sekoia929-ui/Provenar` -- `QUICKSTART.md` covers
the full flow; `toy_agent.py` and `external_bot.py` are complete,
runnable examples.
