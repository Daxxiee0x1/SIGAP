"""Hash-chained, append-only chain-of-custody log.

Each entry commits to the previous entry hash, so rewriting any row breaks every
later hash. This gives detection (via verify_chain and the exported head hash),
not prevention: an admin who rewrites the whole database can recompute the chain,
which is why the head hash should be exported and stored elsewhere.
"""

import hashlib
import json

from .storage import DB, utcnow

GENESIS = "0" * 64
FIELDS = ("prev_entry_hash", "bundle_sha256", "action", "actor", "detail", "timestamp")


def compute_entry_hash(entry: dict) -> str:
    payload = json.dumps({k: entry[k] for k in FIELDS}, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode()).hexdigest()


class CustodyLog:
    def __init__(self, db: DB):
        self.db = db

    def append(self, bundle_sha256: str, action: str, actor: str, detail: str = "") -> dict:
        with self.db.lock:
            row = self.db.conn.execute("SELECT entry_hash FROM custody_log ORDER BY id DESC LIMIT 1").fetchone()
            entry = {
                "prev_entry_hash": row["entry_hash"] if row else GENESIS,
                "bundle_sha256": bundle_sha256,
                "action": action,
                "actor": actor,
                "detail": detail,
                "timestamp": utcnow(),
            }
            entry["entry_hash"] = compute_entry_hash(entry)
            cur = self.db.conn.execute(
                "INSERT INTO custody_log (prev_entry_hash, bundle_sha256, action, actor, detail, timestamp, entry_hash)"
                " VALUES (:prev_entry_hash, :bundle_sha256, :action, :actor, :detail, :timestamp, :entry_hash)",
                entry,
            )
            return {"id": cur.lastrowid, **entry}

    def entries(self, bundle_sha256: str | None = None) -> list[dict]:
        if bundle_sha256:
            rows = self.db.conn.execute(
                "SELECT * FROM custody_log WHERE bundle_sha256 = ? ORDER BY id", (bundle_sha256,)
            ).fetchall()
        else:
            rows = self.db.conn.execute("SELECT * FROM custody_log ORDER BY id").fetchall()
        return [dict(r) for r in rows]

    def head(self) -> dict:
        row = self.db.conn.execute("SELECT id, entry_hash FROM custody_log ORDER BY id DESC LIMIT 1").fetchone()
        return {"head_entry_hash": row["entry_hash"] if row else GENESIS, "count": row["id"] if row else 0}

    def verify_chain(self) -> dict:
        prev = GENESIS
        entries = self.entries()
        for checked, e in enumerate(entries):
            if e["prev_entry_hash"] != prev or compute_entry_hash(e) != e["entry_hash"]:
                return {"ok": False, "broken_at": e["id"], "checked": checked}
            prev = e["entry_hash"]
        return {"ok": True, "broken_at": None, "checked": len(entries), "head_entry_hash": prev}
