"""Simulated IoMT sensor: writes benign telemetry to a log the agent collects."""

import random
import time
from datetime import datetime, timezone
from pathlib import Path

LOG = Path("/var/log/sensor/sensor.log")
MAX_BYTES = 1_000_000


def main() -> None:
    LOG.parent.mkdir(parents=True, exist_ok=True)
    seq = 0
    while True:
        if LOG.exists() and LOG.stat().st_size > MAX_BYTES:
            LOG.replace(LOG.with_suffix(".log.1"))
        seq += 1
        line = (
            f"{datetime.now(timezone.utc).isoformat(timespec='seconds')} seq={seq} "
            f"temp_c={random.uniform(31, 36):.1f} batt_pct={max(5, 100 - seq // 120)} "
            f"gps_fix=3d link={'up' if random.random() > 0.05 else 'degraded'}\n"
        )
        with LOG.open("a") as f:
            f.write(line)
        time.sleep(1)


if __name__ == "__main__":
    main()
