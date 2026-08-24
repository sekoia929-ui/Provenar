"""
toy_agent.py — a minimal external agent, used as the FIRST REAL integration
test of Provenar. This deliberately does NOT import anything from src/ or
reuse Provenar's internal helpers -- it only speaks to Provenar's public
HTTP API and the public chain, exactly like an outside developer would,
because that's the actual thing worth testing: does the interface make
sense to someone who doesn't already know how it's built internally.

What it does, in order:
  1. Registers a fresh agent identity on the real IdentityRegistry
     (mints an ERC-8004 agentId to this script's own wallet).
  2. Makes up a trivial "decision" (a fake trade thesis) and calls
     Provenar's POST /commit -- this seals the decision's hash on-chain
     BEFORE the agent "acts".
  3. Pretends to act on the decision (just a print statement -- this
     script has no real trading logic, on purpose).
  4. Calls validationRequest() on the real ValidationRegistry, naming
     Provenar's adapter as the validator -- the step that makes Provenar's
     later reveal() call to validationResponse() legal on-chain.
  5. Calls Provenar's POST /reveal with the outcome and a score.
  6. Independently reads the result back from the registry directly,
     NOT via Provenar's own /verify endpoint -- so this really is proof
     the score landed on the public, standard registry, not just proof
     Provenar's database says so.

Usage:
    export ROBINHOOD_TESTNET_RPC_URL=https://rpc.testnet.chain.robinhood.com
    export AGENT_PRIVATE_KEY=0x...           # a fresh burner, funded from the faucet
    export IDENTITY_REGISTRY=0xa44f32c6ac995e747f98cdb8a4d822b04af6decd
    export VALIDATION_REGISTRY=0xb765bc96851378c893988e45e5d29fd224fdad7d
    export ADAPTER_ADDRESS=0x2625b77F4cc01208201D85E0914DFAc18852891a
    export PROVENAR_API_URL=http://localhost:8000   # wherever `uvicorn src.main:app` is running

    python3 toy_agent.py
"""
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

    # --- Step 1: register a real identity ---
    print("\n[1] Registering agent identity...")
    receipt = _send(w3, account, identity.functions.register())
    # Decode the Registered event properly rather than guessing at raw log
    # topic positions -- _safeMint() fires an ERC721 Transfer event first,
    # THEN Registered(agentId, agentURI, owner) second, so logs[0] is NOT
    # reliably the Registered event.
    registered_events = identity.events.Registered().process_receipt(receipt)
    if not registered_events:
        raise RuntimeError("register() succeeded but no Registered event found in receipt")
    agent_id = registered_events[0]["args"]["agentId"]
    print(f"    agentId = {agent_id}")

    # --- Step 2: commit a decision via Provenar's public API ---
    print("\n[2] Calling Provenar POST /commit...")
    decision = {
        "action": "buy",
        "market": "TOY/USD",
        "thesis": "toy_agent.py smoke test decision",
        "timestamp": int(time.time()),
    }
    commit_resp = requests.post(
        f"{api_url}/commit", json={"agent_id": agent_id, "decision": decision}, timeout=15
    )
    commit_resp.raise_for_status()
    commit = commit_resp.json()
    print(f"    request_id = {commit['request_id']}")
    print(f"    request_hash = {commit['request_hash']}")
    print(f"    seal tx (via Provenar's operator key) reported by API")

    # --- Step 3: pretend to act ---
    print("\n[3] (Pretending to act on the decision -- no real trade here.)")

    # --- Step 4: agent calls validationRequest, naming Provenar as validator ---
    print("\n[4] Calling validationRequest() on the real registry...")
    request_hash_bytes = bytes.fromhex(commit["request_hash"])
    _send(
        w3,
        account,
        validation.functions.validationRequest(
            adapter_addr, agent_id, "ipfs://toy-agent-request", request_hash_bytes
        ),
    )
    print("    done -- Provenar's adapter is now the named validator for this request")

    # --- Step 5: reveal via Provenar's public API ---
    print("\n[5] Calling Provenar POST /reveal...")
    reveal_resp = requests.post(
        f"{api_url}/reveal",
        json={
            "request_id": commit["request_id"],
            "decision": decision,
            "score": 87,
            "evidence_uri": "https://example.com/toy-agent/fill/1",
            "tag": "toy-agent-smoke-test",
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
    assert status[2] == 87, "score mismatch!"
    print("\n✅ Full loop verified independently: commit -> act -> validationRequest -> reveal -> on-chain score.")


if __name__ == "__main__":
    main()
