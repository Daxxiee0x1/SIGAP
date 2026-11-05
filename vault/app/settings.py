import os
from dataclasses import dataclass, field
from pathlib import Path


def _env(name: str, default: str) -> str:
    return os.environ.get(name, default)


@dataclass(frozen=True)
class Settings:
    data_dir: Path = field(default_factory=lambda: Path(_env("SIGAP_DATA_DIR", "/data/vault")))
    trust_store: Path = field(default_factory=lambda: Path(_env("SIGAP_TRUST_STORE", "/data/trust/trust_store.json")))
    sigap_bin: str = field(default_factory=lambda: _env("SIGAP_BIN", "/usr/local/bin/sigap"))
    token: str = field(default_factory=lambda: _env("SIGAP_VAULT_TOKEN", ""))
    max_bundle_bytes: int = 20 * 1024 * 1024
    rate_limit_per_min: int = 30


settings = Settings()
