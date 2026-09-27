"""Minimal dependency-free Prometheus style metrics registry."""

from __future__ import annotations

import threading
from collections import defaultdict


class Metrics:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._counters: dict[tuple[str, tuple], float] = defaultdict(float)
        self._hist: dict[str, list[float]] = defaultdict(list)

    def inc(self, name: str, value: float = 1.0, labels: dict[str, str] | None = None) -> None:
        key = (name, tuple(sorted((labels or {}).items())))
        with self._lock:
            self._counters[key] += value

    def observe(self, name: str, value: float) -> None:
        with self._lock:
            arr = self._hist[name]
            arr.append(float(value))
            if len(arr) > 5000:
                del arr[: len(arr) - 5000]

    def render(self) -> str:
        lines = []
        with self._lock:
            for (name, labels), v in sorted(self._counters.items()):
                lbl = ",".join(f'{k}="{val}"' for k, val in labels)
                lines.append(f"airt_{name}{{{lbl}}} {v}" if lbl else f"airt_{name} {v}")
            for name, values in self._hist.items():
                if values:
                    s = sorted(values)
                    lines.append(f"airt_{name}_count {len(values)}")
                    lines.append(f"airt_{name}_sum {sum(values)}")
                    lines.append(f"airt_{name}_p50 {s[len(s) // 2]}")
                    lines.append(f"airt_{name}_p95 {s[int(len(s) * 0.95) - 1 if len(s) > 1 else 0]}")
        return "\n".join(lines) + "\n"

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "counters": {f"{n}{dict(labels)}" if labels else n: v for (n, labels), v in self._counters.items()},
                "histograms": {n: len(v) for n, v in self._hist.items()},
            }


metrics = Metrics()
