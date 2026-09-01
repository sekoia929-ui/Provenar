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
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field
from web3 import Web3
from eth_account import Account
from supabase import create_client, Client

app = FastAPI(title="Provenar", version="0.1.0")

# --- storage -----------------------------------------------------------
# Supabase (Postgres) instead of the earlier in-memory dict, so state
# survives server restarts. Uses the service_role key -- this backend is
# the only writer/reader of this table, so RLS is deliberately locked to
# "no public access" (see the migration) and bypassed only from here.
_supabase: Client | None = None


def _get_db() -> Client:
    global _supabase
    if _supabase is None:
        _supabase = create_client(
            os.environ["SUPABASE_URL"], os.environ["SUPABASE_SERVICE_KEY"]
        )
    return _supabase


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

    db = _get_db()
    db.table("commitments").insert(
        {
            "request_id": request_id,
            "agent_id": req.agent_id,
            "decision": req.decision,
            "nonce": nonce,
            "request_hash": request_hash,
            "sealed_at": sealed_at,
            "seal_tx": tx,
            "revealed": False,
        }
    ).execute()

    return CommitResponse(request_id=request_id, request_hash=request_hash, sealed_at=sealed_at)


@app.post("/reveal", response_model=RevealResponse)
async def reveal(req: RevealRequest) -> RevealResponse:
    db = _get_db()
    result = db.table("commitments").select("*").eq("request_id", req.request_id).execute()
    if not result.data:
        raise HTTPException(404, "unknown request_id")
    record = result.data[0]
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

    revealed_at = int(time.time())
    db.table("commitments").update(
        {
            "revealed": True,
            "score": req.score,
            "evidence_uri": req.evidence_uri,
            "tag": req.tag,
            "revealed_at": revealed_at,
            "reveal_tx": tx,
        }
    ).eq("request_id", req.request_id).execute()

    return RevealResponse(
        request_id=req.request_id,
        score=req.score,
        on_chain_tx=tx,
        revealed_at=revealed_at,
    )


def _load_verification(request_id: str) -> dict[str, Any]:
    """Shared by both the JSON /verify endpoint and the HTML /v view."""
    db = _get_db()
    result = db.table("commitments").select("*").eq("request_id", request_id).execute()
    if not result.data:
        raise HTTPException(404, "unknown request_id")
    record = result.data[0]

    checks = {
        "sealed": record["sealed_at"] is not None,
        "revealed": record["revealed"],
        "hash_matches": (
            _canonical_hash(record["agent_id"], record["decision"], record["nonce"])
            == record["request_hash"]
        ),
        "seal_before_reveal": (
            (record["revealed_at"] if record["revealed_at"] is not None else record["sealed_at"] + 1)
            >= record["sealed_at"]
        ),
    }
    checks["all_pass"] = all(checks.values())
    return {"request_id": request_id, "checks": checks, "record": record}


@app.get("/verify/{request_id}")
async def verify(request_id: str) -> dict[str, Any]:
    """
    Independent re-check: recompute the hash from stored plaintext + nonce
    and confirm it matches what was sealed, and that seal preceded reveal.
    In production this should re-derive from on-chain events, not local
    storage, exactly like omo's verify.server.ts does against public RPC.
    """
    return _load_verification(request_id)


@app.get("/v/{request_id}", response_class=HTMLResponse)
async def verify_html(request_id: str) -> str:
    """
    Human-facing view of the same data /verify returns as JSON -- built
    for sharing a specific commitment (e.g. on social media) rather than
    for programmatic use. Not a general product UI; a single shareable
    proof page.
    """
    data = _load_verification(request_id)
    checks = data["checks"]
    record = data["record"]
    decision = record["decision"]

    def badge(ok: bool) -> str:
        return (
            '<span style="color:#4ade80">&#10003; pass</span>'
            if ok
            else '<span style="color:#f87171">&#10007; fail</span>'
        )

    explorer_base = "https://explorer.testnet.chain.robinhood.com/tx/"
    seal_tx = record.get("seal_tx") or ""
    reveal_tx = record.get("reveal_tx") or ""
    seal_link = (
        f'<a href="{explorer_base}{seal_tx}" style="color:#60a5fa">{seal_tx[:14]}...</a>'
        if seal_tx and seal_tx != "unarmed"
        else "unarmed (no chain configured)"
    )
    reveal_link = (
        f'<a href="{explorer_base}{reveal_tx}" style="color:#60a5fa">{reveal_tx[:14]}...</a>'
        if reveal_tx and reveal_tx != "unarmed"
        else "unarmed (no chain configured)"
    )

    overall = (
        '<div style="color:#4ade80;font-size:1.1em">&#10003; ALL CHECKS PASSED</div>'
        if checks["all_pass"]
        else '<div style="color:#f87171;font-size:1.1em">&#10007; VERIFICATION FAILED</div>'
    )

    return f"""
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Provenar — {request_id}</title>
<style>
  body {{ background:#0a0a0a; color:#e5e5e5; font-family: ui-monospace, monospace;
          max-width: 640px; margin: 40px auto; padding: 0 20px; line-height: 1.6; }}
  h1 {{ font-size: 1.3em; color:#f5f5f5; }}
  .card {{ background:#141414; border:1px solid #262626; border-radius:10px;
           padding: 20px; margin: 16px 0; }}
  .label {{ color:#888; font-size:0.85em; text-transform: uppercase; letter-spacing:0.05em; }}
  .row {{ display:flex; justify-content:space-between; padding: 6px 0; border-bottom:1px solid #1f1f1f; }}
  .row:last-child {{ border-bottom:none; }}
  a {{ text-decoration: none; }}
  a:hover {{ text-decoration: underline; }}
  pre {{ background:#0a0a0a; padding:10px; border-radius:6px; overflow-x:auto; font-size:0.85em; }}
</style>
</head>
<body>
  <h1>Provenar &mdash; commit/reveal proof</h1>
  <div class="card">
    {overall}
    <div class="row"><span class="label">sealed</span>{badge(checks['sealed'])}</div>
    <div class="row"><span class="label">revealed</span>{badge(checks['revealed'])}</div>
    <div class="row"><span class="label">hash matches</span>{badge(checks['hash_matches'])}</div>
    <div class="row"><span class="label">seal before reveal</span>{badge(checks['seal_before_reveal'])}</div>
  </div>
  <div class="card">
    <div class="label">agent id</div>
    <div>{record['agent_id']}</div>
    <div class="label" style="margin-top:12px">decision</div>
    <pre>{json.dumps(decision, indent=2)}</pre>
    <div class="label" style="margin-top:12px">score</div>
    <div>{record.get('score', '—')}</div>
  </div>
  <div class="card">
    <div class="label">seal tx</div>
    <div>{seal_link}</div>
    <div class="label" style="margin-top:12px">reveal tx</div>
    <div>{reveal_link}</div>
  </div>
</body>
</html>
"""


@app.get("/", response_class=HTMLResponse)
async def dashboard() -> str:
    """
    A monitor-list-style dashboard of recent commitments, styled after
    Better Stack's monitor list: a status dot, a name, a state, a
    timestamp, each row linking into the full /v/{id} proof page. This
    also replaces the previous bare 404 at the root path with something
    actually useful to land on.
    """
    db = _get_db()
    result = (
        db.table("commitments")
        .select("*")
        .order("sealed_at", desc=True)
        .limit(25)
        .execute()
    )
    records = result.data

    def status_dot(record: dict) -> tuple[str, str]:
        if not record["revealed"]:
            return ("#facc15", "sealed, awaiting reveal")  # yellow
        hash_ok = (
            _canonical_hash(record["agent_id"], record["decision"], record["nonce"])
            == record["request_hash"]
        )
        if hash_ok:
            return ("#4ade80", "verified")  # green
        return ("#f87171", "hash mismatch")  # red

    def fmt_time(ts: int | None) -> str:
        if ts is None:
            return "—"
        return time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(ts))

    def summarize(decision: dict) -> str:
        action = decision.get("action", "?")
        symbol = decision.get("symbol") or decision.get("market", "")
        label = f"{action} {symbol}".strip()
        return label if label != "?" else json.dumps(decision)[:40]

    rows_html = ""
    for r in records:
        color, label = status_dot(r)
        rows_html += f"""
        <a class="row" href="/v/{r['request_id']}">
          <span class="dot" style="background:{color}"></span>
          <span class="name">agent #{r['agent_id']} &mdash; {summarize(r['decision'])}</span>
          <span class="state" style="color:{color}">{label}</span>
          <span class="score">{r.get('score', '—')}</span>
          <span class="time">{fmt_time(r['sealed_at'])}</span>
        </a>"""

    if not records:
        rows_html = '<div class="empty">No commitments yet. Run toy_agent.py or external_bot.py to create one.</div>'

    return f"""
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Provenar</title>
<style>
  body {{ background:#0a0a0a; color:#e5e5e5; font-family: ui-monospace, monospace;
          max-width: 900px; margin: 40px auto; padding: 0 20px; }}
  h1 {{ font-size: 1.4em; margin-bottom: 4px; }}
  .subtitle {{ color:#888; font-size: 0.9em; margin-bottom: 24px; }}
  .card {{ background:#141414; border:1px solid #262626; border-radius:10px; overflow:hidden; }}
  .header {{ display:grid; grid-template-columns: 20px 1fr 160px 60px 180px;
             gap:12px; padding: 12px 16px; color:#888; font-size:0.8em;
             text-transform:uppercase; letter-spacing:0.05em; border-bottom:1px solid #262626; }}
  .row {{ display:grid; grid-template-columns: 20px 1fr 160px 60px 180px;
          gap:12px; align-items:center; padding: 14px 16px; text-decoration:none;
          color:#e5e5e5; border-bottom:1px solid #1f1f1f; }}
  .row:last-child {{ border-bottom:none; }}
  .row:hover {{ background:#1a1a1a; }}
  .dot {{ width:10px; height:10px; border-radius:50%; }}
  .name {{ overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }}
  .state {{ font-size:0.85em; }}
  .score {{ color:#aaa; }}
  .time {{ color:#666; font-size:0.85em; }}
  .empty {{ padding: 40px; text-align:center; color:#888; }}
  .footer {{ margin-top: 20px; color:#666; font-size:0.85em; }}
  a.footer-link {{ color:#60a5fa; text-decoration:none; }}
</style>
</head>
<body>
  <h1>Provenar</h1>
  <div class="subtitle">ERC-8004 Validation Registry provider &mdash; Robinhood Chain testnet</div>
  <div class="card">
    <div class="header">
      <span></span><span>agent / decision</span><span>status</span><span>score</span><span>sealed at</span>
    </div>
    {rows_html}
  </div>
  <div class="footer">
    <a class="footer-link" href="/docs">API docs</a> &middot;
    <a class="footer-link" href="https://github.com/sekoia929-ui/Provenar">source</a>
  </div>
</body>
</html>
"""
