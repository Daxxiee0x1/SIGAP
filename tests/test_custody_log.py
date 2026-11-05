import sqlite3

import pytest

from vault.app.custody_log import CustodyLog
from vault.app.storage import DB


@pytest.fixture()
def log(tmp_path):
    return CustodyLog(DB(tmp_path / "vault.sqlite3"))


def test_chain_is_intact(log):
    for action in ("received", "verified", "reverified"):
        log.append("a" * 64, action, "token:test", "VALID")
    result = log.verify_chain()
    assert result["ok"] and result["checked"] == 3
    assert result["head_entry_hash"] == log.head()["head_entry_hash"]


def test_update_is_blocked_by_trigger(log):
    log.append("a" * 64, "received", "token:test")
    with pytest.raises(sqlite3.IntegrityError):
        log.db.conn.execute("UPDATE custody_log SET detail = 'x'")


def test_rewrite_is_detected(log):
    for action in ("received", "verified", "reverified"):
        log.append("a" * 64, action, "token:test", "VALID")
    # A rogue admin drops the trigger and edits row 2.
    log.db.conn.execute("DROP TRIGGER custody_no_update")
    log.db.conn.execute("UPDATE custody_log SET detail = 'TAMPERED' WHERE id = 2")
    result = log.verify_chain()
    assert result == {"ok": False, "broken_at": 2, "checked": 1}
