"""In-process counters suitable for a Raspberry Pi class node."""

from __future__ import annotations

import time
from collections import defaultdict
from threading import Lock

from src.config import get_settings


class Metrics:
    def __init__(self) -> None:
        self._lock = Lock()
        self.started_at = time.time()
        self.counters: dict[str, int] = defaultdict(int)
        self.latencies_ms: dict[str, list[float]] = defaultdict(list)

    def inc(self, name: str, value: int = 1) -> None:
        if not get_settings().metrics_enabled:
            return
        with self._lock:
            self.counters[name] += value

    def observe(self, name: str, latency_ms: float) -> None:
        if not get_settings().metrics_enabled:
            return
        with self._lock:
            bucket = self.latencies_ms[name]
            bucket.append(latency_ms)
            if len(bucket) > 256:
                del bucket[:128]

    def snapshot(self) -> dict[str, object]:
        with self._lock:
            lat = {
                key: {
                    "count": len(vals),
                    "avg_ms": round(sum(vals) / len(vals), 2) if vals else 0.0,
                    "max_ms": round(max(vals), 2) if vals else 0.0,
                }
                for key, vals in self.latencies_ms.items()
            }
            return {
                "uptime_seconds": round(time.time() - self.started_at, 1),
                "counters": dict(self.counters),
                "latencies": lat,
            }


METRICS = Metrics()
