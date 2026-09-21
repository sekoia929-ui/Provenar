"""
heavy_agent.py — a more substantial test than toy_agent.py or
external_bot.py: ONE agent identity making SEVERAL real decisions across
different stocks, all run through the full commit -> validationRequest ->
reveal -> verify loop. Purpose: give the new /agent/{id} profile page a
genuinely rich history to display (a sparkline needs more than one or two
points to mean anything), not just prove the pipe works once more.

The quotes below are real, live data pulled once via Alpha Vantage
(not fabricated, not simulated) -- hardcoded here rather than fetched by
this script itself, since this script has no market-data API key of its
own (same reasoning as external_bot.py).

Decision rule (still deliberately simple -- this is a rehearsal, not a
real strategy): buy if the stock is up >0.5% on the day, sell if down
more than 0.5%, hold otherwise.

Usage: same env vars as toy_agent.py / external_bot.py:
    export ROBINHOOD_TESTNET_RPC_URL=https://rpc.testnet.chain.robinhood.com
    export AGENT_PRIVATE_KEY=0x...
    export IDENTITY_REGISTRY=0xa44f32c6ac995e747f98cdb8a4d822b04af6decd
    export VALIDATION_REGISTRY=0xb765bc96851378c893988e45e5d29fd224fdad7d
    export ADAPTER_ADDRESS=0x2625b77F4cc01208201D85E0914DFAc18852891a
    export PROVENAR_API_URL=https://provenar.onrender.com

    python3 heavy_agent.py
"""
import os
import time
import requests
from web3 import Web3
from eth_account import Account

# Real quotes, fetched live via Alpha Vantage on 2026-09-18. Not simulated.
QUOTES = [
    {"01. symbol": "AAPL", "05. price": "336.1300", "10. change percent": "-0.2582%"},
    {"01. symbol": "TSLA", "05. price": "364.2700", "10. change percent": "-0.5270%"},
    {"01. symbol": "MSFT", "05. price": "493.7800", "10. change percent": "-0.7976%"},
    {"01. symbol": "GOOGL", "05. price": "349.5400", "10. change percent": "0.6363%"},
    {"01. symbol": "AMZN", "05. price": "253.7100", "10. change percent": "1.0032%"},
]

IDENTITY_ABI = [
    {
        "inputs": [],
        "name": "register",
        "outputs": [{"name": "agentId", "type": "uint256"}],
        "stateMutability": "nonpayable",
        "type": "function",
    },
    {
        "anonymous": False,
        "inputs": [
            {"indexed": True, "name": "agentId", "type": "uint256"},
            {"indexed": False, "name": "agentURI", "type": "string"},
            {"indexed": True, "name": "owner", "type": "address"},
        ],
        "name": "Registered",
        "type": "event",
    },
]

VALIDATION_ABI = [
    {
        "inputs": [
            {"name": "validatorAddress", "type": "address"},
            {"name": "agentId", "type": "uint256"},
            {"name": "requestURI", "type": "string"},
            {"name": "requestHash", "type": "bytes32"},
        ],
        "name": "validationRequest",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function",
    },
]


def _send(w3, account, fn):
    tx = fn.build_transaction(
        {
            "from": account.address,
            "nonce": w3.eth.get_transaction_count(account.address),
            "gasPrice": w3.eth.gas_price,
            "chainId": w3.eth.chain_id,
        }
    )
    signed = account.sign_transaction(tx)
    tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    if receipt.status != 1:
        raise RuntimeError(f"tx reverted: {tx_hash.hex()}")
    return receipt


def make_decision(quote: dict) -> dict:
    symbol = quote["01. symbol"]
    price = float(quote["05. price"])
    change_pct = float(quote["10. change percent"].rstrip("%"))

    if change_pct > 0.5:
        action = "buy"
    elif change_pct < -0.5:
        action = "sell"
    else:
        action = "hold"

    thesis = (
        f"{symbol} is {'up' if change_pct >= 0 else 'down'} {abs(change_pct):.2f}% "
        f"today at ${price:.2f}. Rule: buy>0.5%, sell<-0.5%, else hold."
    )
    return {
        "action": action,
        "symbol": symbol,
        "price": price,
        "change_percent": change_pct,
        "thesis": thesis,
        "timestamp": int(time.time()),
    }


def run_one_cycle(w3, account, identity, validation, adapter_addr, api_url, agent_id, quote):
    decision = make_decision(quote)
    print(f"\n--- {decision['symbol']}: {decision['action'].upper()} ---")
    print(f"    {decision['thesis']}")

    commit_resp = requests.post(
        f"{api_url}/commit", json={"agent_id": agent_id, "decision": decision}, timeout=15
    )
    commit_resp.raise_for_status()
    commit = commit_resp.json()
    print(f"    sealed: {commit['request_id']}")

    request_hash_bytes = bytes.fromhex(commit["request_hash"])
    _send(
        w3,
        account,
        validation.functions.validationRequest(
            adapter_addr, agent_id, f"heavy-agent-{decision['symbol']}", request_hash_bytes
        ),
    )

    score = min(100, max(0, round(50 + decision["change_percent"] * 10)))
    reveal_resp = requests.post(
        f"{api_url}/reveal",
        json={
            "request_id": commit["request_id"],
            "decision": decision,
            "score": score,
            "evidence_uri": f"https://example.com/heavy-agent/{decision['symbol']}/{int(time.time())}",
            "tag": f"heavy-agent-{decision['action']}",
        },
        timeout=30,
    )
    reveal_resp.raise_for_status()
    reveal = reveal_resp.json()
    print(f"    revealed: score={reveal['score']}, tx={reveal['on_chain_tx'][:16]}...")
    return reveal["score"]


def main():
    rpc_url = os.environ["ROBINHOOD_TESTNET_RPC_URL"]
    account = Account.from_key(os.environ["AGENT_PRIVATE_KEY"])
    identity_addr = Web3.to_checksum_address(os.environ["IDENTITY_REGISTRY"])
    validation_addr = Web3.to_checksum_address(os.environ["VALIDATION_REGISTRY"])
    adapter_addr = Web3.to_checksum_address(os.environ["ADAPTER_ADDRESS"])
    api_url = os.environ.get("PROVENAR_API_URL", "http://localhost:8000")

    w3 = Web3(Web3.HTTPProvider(rpc_url))
    identity = w3.eth.contract(address=identity_addr, abi=IDENTITY_ABI)
    validation = w3.eth.contract(address=validation_addr, abi=VALIDATION_ABI)

    print(f"Agent wallet: {account.address}")
    balance = w3.eth.get_balance(account.address)
    print(f"Balance: {balance} wei")
    if balance == 0:
        raise SystemExit("Fund this wallet from https://faucet.testnet.chain.robinhood.com first.")

    print("\n[1] Registering ONE agent identity for this whole run...")
    receipt = _send(w3, account, identity.functions.register())
    registered_events = identity.events.Registered().process_receipt(receipt)
    agent_id = registered_events[0]["args"]["agentId"]
    print(f"    agentId = {agent_id}")

    print(f"\n[2] Running {len(QUOTES)} real decisions under this one agent...")
    scores = []
    for quote in QUOTES:
        # Rate limit is 10 commits/hour and 20 reveals/hour per IP -- 5
        # cycles is comfortably under that, no throttling needed here.
        score = run_one_cycle(
            w3, account, identity, validation, adapter_addr, api_url, agent_id, quote
        )
        scores.append(score)

    print(f"\n✅ Done. {len(scores)} real decisions sealed and revealed under agent #{agent_id}.")
    print(f"   Scores: {scores}")
    print(f"   View the full track record: {api_url}/agent/{agent_id}")


if __name__ == "__main__":
    main()
