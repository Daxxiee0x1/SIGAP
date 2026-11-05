import json
import zipfile

import pytest

from tools import make_tampered as mt


def test_valid_bundle(sigap, bundle):
    result = sigap.verify(bundle)
    assert result["status"] == "VALID", result["reasons"]
    assert result["exit_code"] == 0


@pytest.mark.parametrize("variant", sorted(mt.VARIANTS))
def test_manipulated_bundle(sigap, bundle, tmp_path, variant):
    make, expected = mt.VARIANTS[variant]
    out = tmp_path / f"{variant}.zip"
    make(bundle, out)
    result = sigap.verify(out)
    assert result["status"] == expected, result["reasons"]
    assert result["exit_code"] != 0


def test_foreign_key_is_untrusted(sigap, foreign_bundle):
    result = sigap.verify(foreign_bundle)
    assert result["status"] == "UNTRUSTED_SIGNER"
    assert result["exit_code"] == 4


def test_config_is_redacted_before_hashing(bundle):
    with zipfile.ZipFile(bundle) as z:
        config = z.read("artifacts/config_redacted.txt").decode()
        manifest = json.loads(z.read("manifest.json"))
    assert "demo-secret-123" not in config
    assert "api_key=[REDACTED]" in config
    entry = next(a for a in manifest["artifacts"] if a["name"] == "config_redacted")
    assert entry["redactions"] == 1
