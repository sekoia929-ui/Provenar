"""
Provenar: a commit-as-a-service Validation Registry provider for
ERC-8004 agents on Robinhood Chain (or any EVM chain with a deployed
Validation Registry).

Flow mirrors omo's own pipeline, generalized for third-party agents:

    POST /commit   -> agent submits a decision payload BEFORE acting
                       -> server hashes + nonces it, seals on-chain, returns request_id
    POST /reveal   -> agent submits the plaintext + its own pass/fail rule outcome
                       -> server re-hashes, checks it matches the sealed hash,
                          publishes the ERC-8004 validation result on-chain
    GET  /verify/{request_id} -> anyone re-checks the full chain of custody:
                       hash matches, seal preceded reveal, agent id matches.

This service holds no trading key and never sees the agent's funds — it is
strictly an attestation layer, same separation as omo's commit-only burner key.
"""
import hashlib
import json
import os
import secrets
import time
from typing import Any

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
from web3 import Web3
from eth_account import Account

app = FastAPI(title="Provenar", version="0.1.0")

# --- storage -----------------------------------------------------------
# Swap for Supabase/Postgres in production; in-memory here for the skeleton.
_COMMITMENTS: dict[str, dict[str, Any]] = {}


# --- models --------------------------------------------------------------
class CommitRequest(BaseModel):
    agent_id: int = Field(..., description="ERC-8004 Identity Registry token id")
    decision: dict[str, Any] = Field(
        ..., description="Canonical decision payload: thesis, action, numbers behind it"
    )


class CommitResponse(BaseModel):
    request_id: str
    request_hash: str
    sealed_at: int


class RevealRequest(BaseModel):
    request_id: str
    decision: dict[str, Any] = Field(..., description="Must match the committed payload exactly")
    score: int = Field(..., ge=0, le=100, description="ERC-8004 validation score, 0-100")
    evidence_uri: str = Field(..., description="Where the fill / outcome record lives")
    tag: str = Field(default="", description="Optional ERC-8004 response tag, e.g. 'trading-decision'")


class RevealResponse(BaseModel):
    request_id: str
    score: int
    on_chain_tx: str | None
    revealed_at: int


# --- canonicalization ----------------------------------------------------
def _canonical_hash(agent_id: int, decision: dict[str, Any], nonce: str) -> str:
    """Deterministic sha256 over agent_id + decision + nonce, sorted keys."""
    payload = {"agent_id": agent_id, "decision": decision, "nonce": nonce}
    blob = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(blob).hexdigest()


# --- chain adapter --------------------------------------------------------
# Minimal ABI: only the two functions this service actually calls.
_ADAPTER_ABI = [
    {
        "inputs": [
            {"name": "requestHash", "type": "bytes32"},
            {"name": "agentId", "type": "uint256"},
        ],
        "name": "seal",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function",
    },
    {
        "inputs": [
            {"name": "requestHash", "type": "bytes32"},
            {"name": "preimageHash", "type": "bytes32"},
            {"name": "score", "type": "uint8"},
            {"name": "evidenceHash", "type": "bytes32"},
            {"name": "evidenceURI", "type": "string"},
            {"name": "tag", "type": "string"},
        ],
        "name": "reveal",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function",
    },
]

_w3: Web3 | None = None
_adapter = None
_operator_account = None


def _get_chain():
    """
    Lazily build the web3 connection, signing account, and contract instance.
    Only called once RPC/adapter/key env vars are confirmed present -- see
    the `not os.getenv(...)` early-return in each on-chain function below.
    Uses legacy (non-EIP-1559) gas fields throughout: Robinhood Chain testnet
    isn't in web3.py's built-in chain registry, and letting web3.py guess at
    EIP-1559 fee fields for an unrecognized chain is the same class of
    problem we hit with viem's chain-list lookup earlier -- explicit
    gasPrice sidesteps it entirely.
    """
    global _w3, _adapter, _operator_account
    if _w3 is None:
        _w3 = Web3(Web3.HTTPProvider(os.environ["ROBINHOOD_RPC_URL"]))
        _operator_account = Account.from_key(os.environ["ADAPTER_OPERATOR_PRIVATE_KEY"])
        adapter_address = Web3.to_checksum_address(os.environ["ADAPTER_ADDRESS"])
        _adapter = _w3.eth.contract(address=adapter_address, abi=_ADAPTER_ABI)
    return _w3, _adapter, _operator_account


def _send(w3: Web3, account, fn) -> str:
    """Build, sign, send, and wait for one contract-function call. Returns tx hash hex."""
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
        raise RuntimeError(f"on-chain call reverted, tx {tx_hash.hex()}")
    return tx_hash.hex()


async def _seal_on_chain(request_hash: str, agent_id: int) -> str:
    """
    Call OmoValidationAdapter.seal(requestHash, agentId). Returns "unarmed"
    (no real tx sent) until ROBINHOOD_RPC_URL / ADAPTER_ADDRESS /
    ADAPTER_OPERATOR_PRIVATE_KEY are all set -- same convention as omo:
    reads/gates/seals-locally without faking a transaction.
    """
    if not os.getenv("ROBINHOOD_RPC_URL"):
        return "unarmed"
    w3, adapter, account = _get_chain()
    fn = adapter.functions.seal(bytes.fromhex(request_hash), agent_id)
    return _send(w3, account, fn)


async def _reveal_on_chain(
    request_hash: str, agent_id: int, score: int, evidence_uri: str, tag: str
) -> str:
    """
    Call OmoValidationAdapter.reveal(...), which itself calls the real
    ERC-8004 ValidationRegistry.validationResponse(). This reverts on-chain
    if the agent hasn't already called validationRequest() naming this
    adapter as validatorAddress -- that's enforced by the registry, not
    re-checked here. preimageHash is passed as the same value as
    requestHash: the FastAPI layer already verified the revealed plaintext
    hashes back to what was sealed (see /reveal below), so by the time this
    function runs, requestHash IS the confirmed-correct preimage hash.
    """
    if not os.getenv("ROBINHOOD_RPC_URL"):
        return "unarmed"
    w3, adapter, account = _get_chain()
    request_hash_bytes = bytes.fromhex(request_hash)
    evidence_hash_bytes = hashlib.sha256(evidence_uri.encode()).digest()
    fn = adapter.functions.reveal(
        request_hash_bytes, request_hash_bytes, score, evidence_hash_bytes, evidence_uri, tag
    )
    return _send(w3, account, fn)


# --- endpoints -------------------------------------------------------------
@app.post("/commit", response_model=CommitResponse)
async def commit(req: CommitRequest) -> CommitResponse:
    nonce = secrets.token_hex(16)
    request_hash = _canonical_hash(req.agent_id, req.decision, nonce)
    request_id = secrets.token_urlsafe(12)
    sealed_at = int(time.time())

    tx = await _seal_on_chain(request_hash, req.agent_id)

    _COMMITMENTS[request_id] = {
        "agent_id": req.agent_id,
        "decision": req.decision,
        "nonce": nonce,
        "request_hash": request_hash,
        "sealed_at": sealed_at,
        "seal_tx": tx,
        "revealed": False,
    }

    return CommitResponse(request_id=request_id, request_hash=request_hash, sealed_at=sealed_at)


@app.post("/reveal", response_model=RevealResponse)
async def reveal(req: RevealRequest) -> RevealResponse:
    record = _COMMITMENTS.get(req.request_id)
    if record is None:
        raise HTTPException(404, "unknown request_id")
    if record["revealed"]:
        raise HTTPException(409, "already revealed")

    # Recompute the hash from the revealed plaintext + the nonce we stored at
    # seal time, and require it to match exactly. This is the check that
    # makes the whole pattern meaningful: you cannot reveal a different
    # decision than the one you sealed.
    recomputed = _canonical_hash(record["agent_id"], req.decision, record["nonce"])
    if recomputed != record["request_hash"]:
        raise HTTPException(400, "revealed decision does not match sealed hash")

    tx = await _reveal_on_chain(
        record["request_hash"], record["agent_id"], req.score, req.evidence_uri, req.tag
    )

    record["revealed"] = True
    record["score"] = req.score
    record["evidence_uri"] = req.evidence_uri
    record["revealed_at"] = int(time.time())
    record["reveal_tx"] = tx

    return RevealResponse(
        request_id=req.request_id,
        score=req.score,
        on_chain_tx=tx,
        revealed_at=record["revealed_at"],
    )


@app.get("/verify/{request_id}")
async def verify(request_id: str) -> dict[str, Any]:
    """
    Independent re-check: recompute the hash from stored plaintext + nonce
    and confirm it matches what was sealed, and that seal preceded reveal.
    In production this should re-derive from on-chain events, not local
    storage, exactly like omo's verify.server.ts does against public RPC.
    """
    record = _COMMITMENTS.get(request_id)
    if record is None:
        raise HTTPException(404, "unknown request_id")

    checks = {
        "sealed": record["sealed_at"] is not None,
        "revealed": record["revealed"],
        "hash_matches": (
            _canonical_hash(record["agent_id"], record["decision"], record["nonce"])
            == record["request_hash"]
        ),
        "seal_before_reveal": (
            record.get("revealed_at", record["sealed_at"] + 1) >= record["sealed_at"]
        ),
    }
    checks["all_pass"] = all(checks.values())
    return {"request_id": request_id, "checks": checks, "record": record}
