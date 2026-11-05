"""SIGAP Vault: receives bundles, re-verifies them with the Go verifier, and records
chain of custody in a hash-chained log. Every bundle is untrusted input."""

import hashlib
import hmac
import re
import time
from collections import defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path

from fastapi import Depends, FastAPI, File, Form, Header, HTTPException, Request, UploadFile
from fastapi.staticfiles import StaticFiles

from .custody_log import CustodyLog
from .settings import settings
from .storage import DB
from .verifier_bridge import VerifierError, verify_bundle

# No Swagger UI: it loads assets from a CDN, which conflicts with offline use and the CSP.
app = FastAPI(title="SIGAP Vault", version="1.0.0", docs_url=None, redoc_url=None)
db = DB(settings.data_dir / "vault.sqlite3")
custody = CustodyLog(db)
BUNDLE_DIR = settings.data_dir / "bundles"
BUNDLE_DIR.mkdir(parents=True, exist_ok=True)
STATIC_DIR = Path(__file__).resolve().parent.parent / "static"
SHA_RE = re.compile(r"^[0-9a-f]{64}$")

CSP = (
    "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; "
    "connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["Content-Security-Policy"] = CSP
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response


_hits: dict[str, deque] = defaultdict(deque)


def rate_limit(request: Request) -> None:
    ip = request.client.host if request.client else "unknown"
    now = time.monotonic()
    q = _hits[ip]
    while q and now - q[0] > 60:
        q.popleft()
    if len(q) >= settings.rate_limit_per_min:
        raise HTTPException(429, "terlalu banyak permintaan")
    q.append(now)


def require_token(authorization: str = Header(default="")) -> str:
    if not settings.token:
        raise HTTPException(503, "SIGAP_VAULT_TOKEN belum diset")
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not hmac.compare_digest(token.encode(), settings.token.encode()):
        raise HTTPException(401, "token tidak valid")
    # Actor identity = short fingerprint of the token, never the token itself.
    return "token:" + hashlib.sha256(token.encode()).hexdigest()[:8]


def run_verifier(path: Path) -> dict:
    try:
        return verify_bundle(path)
    except VerifierError as exc:
        raise HTTPException(503, str(exc)) from exc


def bundle_or_404(sha: str) -> dict:
    if not SHA_RE.match(sha):
        raise HTTPException(400, "hash bundle tidak valid")
    bundle = db.get_bundle(sha)
    if not bundle:
        raise HTTPException(404, "bundle tidak ditemukan")
    return bundle


@app.post("/api/bundles", dependencies=[Depends(rate_limit)])
def submit_bundle(
    file: UploadFile = File(...),
    note: str = Form(default="", max_length=500),
    actor: str = Depends(require_token),
):
    data = file.file.read(settings.max_bundle_bytes + 1)
    if len(data) > settings.max_bundle_bytes:
        raise HTTPException(413, "bundle melebihi 20 MB")
    sha = hashlib.sha256(data).hexdigest()

    existing = db.get_bundle(sha)
    if existing:  # replay / duplicate: record it, never process again
        custody.append(sha, "duplicate_ignored", actor, "hash bundle sudah tercatat")
        return {"bundle_sha256": sha, "duplicate": True, "status": existing["status"]}

    path = BUNDLE_DIR / f"{sha}.zip"  # stored under its hash, never the client filename
    path.write_bytes(data)
    custody.append(sha, "received", actor, note)
    result = run_verifier(path)
    db.insert_bundle(sha, result, note)
    custody.append(sha, "verified", "vault-verifier", result["status"])
    return {"bundle_sha256": sha, "duplicate": False, "status": result["status"], "reasons": result["reasons"]}


@app.get("/api/bundles")
def list_bundles():
    return [
        {k: b[k] for k in ("bundle_sha256", "bundle_id", "node_id", "key_id", "status", "received_at", "last_verified_at")}
        for b in db.list_bundles()
    ]


@app.get("/api/bundles/{sha}")
def get_bundle(sha: str):
    bundle = bundle_or_404(sha)
    return {**bundle, "custody": custody.entries(sha)}


@app.post("/api/bundles/{sha}/reverify", dependencies=[Depends(rate_limit)])
def reverify(sha: str, actor: str = Depends(require_token)):
    bundle_or_404(sha)
    result = run_verifier(BUNDLE_DIR / f"{sha}.zip")
    db.update_verification(sha, result)
    custody.append(sha, "reverified", actor, result["status"])
    return {"bundle_sha256": sha, "status": result["status"], "reasons": result["reasons"]}


@app.get("/api/custody")
def custody_entries():
    return {"entries": custody.entries(), **custody.head()}


@app.get("/api/custody/verify")
def custody_verify():
    return custody.verify_chain()


@app.get("/api/custody/head")
def custody_head():
    """Export this and keep it off the vault host to detect later rewrites."""
    return {**custody.head(), "exported_at": datetime.now(timezone.utc).isoformat(timespec="seconds")}


app.mount("/", StaticFiles(directory=STATIC_DIR, html=True), name="dashboard")
