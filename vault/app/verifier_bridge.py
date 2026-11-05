"""Delegates verification to the Go binary so node, analyst laptop, and vault all
run exactly one implementation (internal/verify). Python never unzips bundles."""

import json
import subprocess
from pathlib import Path

from .settings import settings

STATUSES = {"VALID", "TAMPERED", "INCOMPLETE", "UNTRUSTED_SIGNER", "MALFORMED"}


class VerifierError(RuntimeError):
    pass


def verify_bundle(path: Path) -> dict:
    cmd = [settings.sigap_bin, "verify", "--json", "--trust", str(settings.trust_store), str(path)]
    try:
        proc = subprocess.run(cmd, capture_output=True, timeout=15, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise VerifierError(f"verifier gagal dijalankan: {exc}") from exc
    try:
        result = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        stderr = proc.stderr.decode(errors="replace")[:300]
        raise VerifierError(f"keluaran verifier tidak valid (exit {proc.returncode}): {stderr}") from exc
    if result.get("status") not in STATUSES:
        raise VerifierError("status verifier tidak dikenal")
    return result
