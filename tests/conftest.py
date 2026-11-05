import json
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


@dataclass
class Sigap:
    bin: Path
    trust: Path

    def run(self, *args) -> subprocess.CompletedProcess:
        return subprocess.run([str(self.bin), *map(str, args)], capture_output=True, text=True, check=True)

    def verify(self, bundle: Path) -> dict:
        proc = subprocess.run(
            [str(self.bin), "verify", "--json", "--trust", str(self.trust), str(bundle)],
            capture_output=True,
            text=True,
        )
        return {**json.loads(proc.stdout), "exit_code": proc.returncode}


@pytest.fixture(scope="session")
def workdir(tmp_path_factory) -> Path:
    return tmp_path_factory.mktemp("sigap")


@pytest.fixture(scope="session")
def sigap(workdir) -> Sigap:
    if shutil.which("go") is None:
        pytest.skip("Go toolchain tidak tersedia")
    out = workdir / "sigap"
    subprocess.run(["go", "build", "-o", str(out), "./cmd/sigap"], cwd=ROOT, check=True)
    return Sigap(out, workdir / "trust_store.json")


def _collect(sigap: Sigap, workdir: Path, name: str, enroll: bool) -> Path:
    node = workdir / name
    node.mkdir()
    log = node / "sensor.log"
    log.write_text("telemetry ok\n" * 50)
    conf = node / "sensor.conf"
    conf.write_text("mode=patrol\napi_key=demo-secret-123\n")
    key = node / "node.key"
    args = ["keygen", "--key-id", f"node-{name}-a", "--out", key]
    if enroll:
        args += ["--trust", sigap.trust]
    sigap.run(*args)
    cfg = node / "agent.json"
    cfg.write_text(
        json.dumps(
            {
                "node_id": name,
                "proc_root": "/proc",
                "key_file": str(key),
                "outbox": str(node / "outbox"),
                "log_files": [str(log)],
                "config_files": [str(conf)],
            }
        )
    )
    sigap.run("collect", "--config", cfg, "--trigger", "pytest")
    return next((node / "outbox").glob("*.zip"))


@pytest.fixture(scope="session")
def bundle(sigap, workdir) -> Path:
    return _collect(sigap, workdir, "sensor-test", enroll=True)


@pytest.fixture(scope="session")
def foreign_bundle(sigap, workdir, bundle) -> Path:
    # Signed by a valid Ed25519 key that was never enrolled in the trust store.
    return _collect(sigap, workdir, "attacker", enroll=False)
