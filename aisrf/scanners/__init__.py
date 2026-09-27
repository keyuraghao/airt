"""External scan-engine integrations for AISRF.

Each engine (garak, promptfoo, PyRIT, PyRIT-Ship) implements the ScanEngine protocol and registers
itself in `registry`. Engines drive their probes at the target model through the AISRF gateway, so
every adversarial prompt becomes a ticket that is analysed, policy checked and human approved, and
they persist results as Campaign + ProbeResult rows in the native shape the dashboard and reports
already understand.

Importing this package registers all engines and exposes `router` (mount at /api/scanners) and
`ship_router` (mount at /api/pyrit-ship).
"""
from __future__ import annotations

from . import base
from .base import ScanEngine, registry, scan_runner
from .garak import engine as garak_engine
from .promptfoo import engine as promptfoo_engine
from .pyrit import engine as pyrit_engine
from .pyrit_ship import engine as pyrit_ship_engine

base.register(garak_engine)
base.register(promptfoo_engine)
base.register(pyrit_engine)
base.register(pyrit_ship_engine)

from .router import router, ship_router  # noqa: E402  (import after engines register)

__all__ = ["ScanEngine", "base", "registry", "router", "scan_runner", "ship_router"]
