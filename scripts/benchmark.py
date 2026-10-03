"""Simple CPU benchmark for startup and request latency."""

from __future__ import annotations

import statistics
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from fastapi.testclient import TestClient


def main() -> None:
    started = time.perf_counter()
    from src.api import app

    startup_ms = (time.perf_counter() - started) * 1000
    client = TestClient(app)
    client.get("/health")
    samples = []
    for _ in range(20):
        t0 = time.perf_counter()
        client.post("/api/v1/analyze/message", json={"message": "hello from the office calendar"})
        samples.append((time.perf_counter() - t0) * 1000)
    print(f"import_and_app_ms={startup_ms:.1f}")
    print(f"analyze_message_avg_ms={statistics.mean(samples):.1f}")
    print(f"analyze_message_p95_ms={sorted(samples)[int(0.95 * (len(samples) - 1))]:.1f}")
    try:
        import resource

        rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        print(f"maxrss_kb_or_bytes={rss}")
    except Exception:
        print("memory_metric=unavailable_on_this_os")


if __name__ == "__main__":
    main()
