"""Optional structured audit log of allowed and denied calls."""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

from .config import AuditConfig


class Audit:
    """Writes one JSON object per line: capability, path, decision, reason.

    Disabled by default. When enabled with no path, logs to stderr so it never
    contaminates the stdio MCP channel (stdout).
    """

    def __init__(self, config: AuditConfig) -> None:
        self.enabled = config.enabled
        self._path = Path(config.path) if config.path else None

    def record(self, capability: str, path: str, decision: str, reason: str | None = None) -> None:
        if not self.enabled:
            return
        entry = {
            "ts": time.time(),
            "capability": capability,
            "path": path,
            "decision": decision,  # "allow" | "deny"
        }
        if reason:
            entry["reason"] = reason
        line = json.dumps(entry, ensure_ascii=False)
        if self._path is not None:
            with self._path.open("a", encoding="utf-8") as fh:
                fh.write(line + "\n")
        else:
            print(line, file=sys.stderr, flush=True)

    def allow(self, capability: str, path: str) -> None:
        self.record(capability, path, "allow")

    def deny(self, capability: str, path: str, reason: str) -> None:
        self.record(capability, path, "deny", reason)
