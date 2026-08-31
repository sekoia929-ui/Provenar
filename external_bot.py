"""
external_bot.py — a more realistic stress-test than toy_agent.py.

Still not a genuinely third-party test (same author, same inside
knowledge of Provenar's internals) -- but unlike toy_agent.py, this one
makes an actual decision from real live market data instead of a
hardcoded fake payload, closer to what a real trading agent's commit
payload would look like.

Decision rule (deliberately simple, on purpose -- this is a rehearsal,
not a real strategy): BUY if the stock is up more than 1% on the day,
HOLD otherwise. Real money is never involved; this only ever calls
Provenar's API and the public chain, exactly like toy_agent.py does.

Usage: same env vars as toy_agent.py, plus:
    export QUOTE_SYMBOL=NVDA          # optional, defaults to NVDA
    export QUOTE_JSON='{"price": "220.78", "change_percent": "1.4847%", ...}'
                                        # the live quote, passed in as JSON
                                        # rather than fetched here, since
                                        # this script has no market-data
                                        # API key of its own
"""
import json
import os
import time
import requests
from web3 import Web3
from eth_account import Account

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
    {
        "inputs": [{"name": "requestHash", "type": "bytes32"}],
        "name": "getValidationStatus",
        "outputs": [
            {"name": "validatorAddress", "type": "address"},
            {"name": "agentId", "type": "uint256"},
            {"name": "response", "type": "uint8"},
            {"name": "responseHash", "type": "bytes32"},
            {"name": "tag", "type": "string"},
            {"name": "lastUpdate", "type": "uint256"},
        ],
        "stateMutability": "view",
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


def make_decision(symbol: str, quote: dict) -> dict:
    """Real (if simple) decision logic, not a hardcoded fake payload."""
    price = float(quote["05. price"])
    change_pct_str = quote["10. change percent"].rstrip("%")
    change_pct = float(change_pct_str)

    action = "buy" if change_pct > 1.0 else "hold"
    thesis = (
        f"{symbol} is {'up' if change_pct >= 0 else 'down'} {abs(change_pct):.2f}% "
        f"today at ${price:.2f}. Rule: buy if daily change > 1%, else hold."
    )

    return {
        "action": action,
        "symbol": symbol,
        "price": price,
        "change_percent": change_pct,
        "thesis": thesis,
        "timestamp": int(time.time()),
    }


def main():
    rpc_url = os.environ["ROBINHOOD_TESTNET_RPC_URL"]
    account = Account.from_key(os.environ["AGENT_PRIVATE_KEY"])
    identity_addr = Web3.to_checksum_address(os.environ["IDENTITY_REGISTRY"])
    validation_addr = Web3.to_checksum_address(os.environ["VALIDATION_REGISTRY"])
    adapter_addr = Web3.to_checksum_address(os.environ["ADAPTER_ADDRESS"])
    api_url = os.environ.get("PROVENAR_API_URL", "http://localhost:8000")
    symbol = os.environ.get("QUOTE_SYMBOL", "NVDA")
    quote = json.loads(os.environ["QUOTE_JSON"])

    w3 = Web3(Web3.HTTPProvider(rpc_url))
    identity = w3.eth.contract(address=identity_addr, abi=IDENTITY_ABI)
    validation = w3.eth.contract(address=validation_addr, abi=VALIDATION_ABI)

    print(f"Agent wallet: {account.address}")
    balance = w3.eth.get_balance(account.address)
    print(f"Balance: {balance} wei")
    if balance == 0:
        raise SystemExit("Fund this wallet from https://faucet.testnet.chain.robinhood.com first.")

    # --- Step 0: make a real decision from real data ---
    decision = make_decision(symbol, quote)
    print(f"\n[0] Decision: {decision['action'].upper()} -- {decision['thesis']}")

    # --- Step 1: register a real identity ---
    print("\n[1] Registering agent identity...")
    receipt = _send(w3, account, identity.functions.register())
    registered_events = identity.events.Registered().process_receipt(receipt)
    if not registered_events:
        raise RuntimeError("register() succeeded but no Registered event found in receipt")
    agent_id = registered_events[0]["args"]["agentId"]
    print(f"    agentId = {agent_id}")

    # --- Step 2: commit the real decision ---
    print("\n[2] Calling Provenar POST /commit...")
    commit_resp = requests.post(
        f"{api_url}/commit", json={"agent_id": agent_id, "decision": decision}, timeout=15
    )
    commit_resp.raise_for_status()
    commit = commit_resp.json()
    print(f"    request_id = {commit['request_id']}")
    print(f"    request_hash = {commit['request_hash']}")

    # --- Step 3: act (still simulated -- no real trade) ---
    print(f"\n[3] (Pretending to {decision['action']} {symbol} -- no real trade here.)")

    # --- Step 4: agent calls validationRequest, naming Provenar as validator ---
    print("\n[4] Calling validationRequest() on the real registry...")
    request_hash_bytes = bytes.fromhex(commit["request_hash"])
    _send(
        w3,
        account,
        validation.functions.validationRequest(
            adapter_addr, agent_id, f"real-quote-{symbol}", request_hash_bytes
        ),
    )
    print("    done -- Provenar's adapter is now the named validator for this request")

    # --- Step 5: reveal the real outcome ---
    print("\n[5] Calling Provenar POST /reveal...")
    # A real score here would come from checking the decision against the
    # actual gate rules; this rehearsal just confirms the rule was applied
    # consistently (buy-signal strength maps to score).
    score = min(100, max(0, round(50 + decision["change_percent"] * 10)))
    reveal_resp = requests.post(
        f"{api_url}/reveal",
        json={
            "request_id": commit["request_id"],
            "decision": decision,
            "score": score,
            "evidence_uri": f"https://example.com/external-bot/{symbol}/{int(time.time())}",
            "tag": f"external-bot-{decision['action']}",
        },
        timeout=30,
    )
    reveal_resp.raise_for_status()
    reveal = reveal_resp.json()
    print(f"    score = {reveal['score']}")
    print(f"    on_chain_tx = {reveal['on_chain_tx']}")

    # --- Step 6: independently verify, NOT via Provenar's own API ---
    print("\n[6] Independently reading the registry directly (not via Provenar)...")
    status = validation.functions.getValidationStatus(request_hash_bytes).call()
    print(f"    validatorAddress = {status[0]}")
    print(f"    agentId          = {status[1]}")
    print(f"    response (score) = {status[2]}")
    print(f"    tag               = {status[4]}")

    assert status[0].lower() == adapter_addr.lower(), "validator mismatch!"
    assert status[1] == agent_id, "agentId mismatch!"
    assert status[2] == score, "score mismatch!"
    print(f"\n✅ Real decision, real data, full loop verified: {decision['action'].upper()} {symbol} @ ${decision['price']:.2f}")


if __name__ == "__main__":
    main()
