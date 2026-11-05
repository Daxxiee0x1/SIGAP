"""SQLite storage. Bundles may be re-verified (row updated); custody_log is append-only."""

import json
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS bundles (
  bundle_sha256    TEXT PRIMARY KEY,
  bundle_id        TEXT,
  node_id          TEXT,
  key_id           TEXT,
  status           TEXT NOT NULL,
  reasons          TEXT NOT NULL,
  manifest         TEXT,
  note             TEXT NOT NULL DEFAULT '',
  received_at      TEXT NOT NULL,
  last_verified_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS custody_log (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,
  prev_entry_hash TEXT NOT NULL,
  bundle_sha256   TEXT NOT NULL,
  action          TEXT NOT NULL,
  actor           TEXT NOT NULL,
  detail          TEXT NOT NULL,
  timestamp       TEXT NOT NULL,
  entry_hash      TEXT NOT NULL UNIQUE
);
CREATE TRIGGER IF NOT EXISTS custody_no_update BEFORE UPDATE ON custody_log
BEGIN SELECT RAISE(ABORT, 'custody_log is append-only'); END;
CREATE TRIGGER IF NOT EXISTS custody_no_delete BEFORE DELETE ON custody_log
BEGIN SELECT RAISE(ABORT, 'custody_log is append-only'); END;
"""


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class DB:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.executescript(SCHEMA)
        self.lock = threading.Lock()

    def get_bundle(self, sha: str) -> dict | None:
        row = self.conn.execute("SELECT * FROM bundles WHERE bundle_sha256 = ?", (sha,)).fetchone()
        return _decode(row) if row else None

    def list_bundles(self) -> list[dict]:
        rows = self.conn.execute("SELECT * FROM bundles ORDER BY received_at DESC").fetchall()
        return [_decode(r) for r in rows]

    def insert_bundle(self, sha: str, result: dict, note: str) -> None:
        manifest = result.get("manifest") or {}
        now = utcnow()
        with self.lock:
            self.conn.execute(
                "INSERT INTO bundles VALUES (?,?,?,?,?,?,?,?,?,?)",
                (
                    sha,
                    manifest.get("bundle_id"),
                    manifest.get("node_id"),
                    result.get("key_id"),
                    result["status"],
                    json.dumps(result.get("reasons", [])),
                    json.dumps(manifest) if manifest else None,
                    note,
                    now,
                    now,
                ),
            )

    def update_verification(self, sha: str, result: dict) -> None:
        with self.lock:
            self.conn.execute(
                "UPDATE bundles SET status = ?, reasons = ?, last_verified_at = ? WHERE bundle_sha256 = ?",
                (result["status"], json.dumps(result.get("reasons", [])), utcnow(), sha),
            )


def _decode(row: sqlite3.Row) -> dict:
    d = dict(row)
    d["reasons"] = json.loads(d["reasons"])
    d["manifest"] = json.loads(d["manifest"]) if d["manifest"] else None
    return d
