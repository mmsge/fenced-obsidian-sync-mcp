"""Obsidian Sync management for ``mode: sync``.

Wraps the official ``obsidian-headless`` client (``ob sync --continuous``) as a
child process so the local vault directory mirrors Obsidian Sync. This module
does not reimplement syncing; it only supervises the official client.

The client must already be authenticated and the vault linked — a one-time
``ob login`` followed by ``ob sync-setup --vault "<name>" --path <vault_dir>``,
whose state persists in the client's config directory. ``ob sync --continuous``
then operates on the configured vault from within ``vault_dir`` (its working
directory); it takes no ``--vault`` flag.

In ``mode: local`` this module is never used — there is no ``obsidian-headless``
dependency and no subprocess.
"""

from __future__ import annotations

import shutil
import subprocess
import sys

from .config import Config


class SyncManager:
    """Start/stop and monitor an ``ob sync --continuous`` subprocess."""

    def __init__(self, config: Config, ob_binary: str = "ob") -> None:
        if config.mode != "sync":
            raise ValueError("SyncManager is only valid for mode: sync")
        self._config = config
        self._ob = ob_binary
        self._proc: subprocess.Popen | None = None

    @property
    def running(self) -> bool:
        return self._proc is not None and self._proc.poll() is None

    def start(self) -> None:
        if shutil.which(self._ob) is None:
            raise FileNotFoundError(
                f"'{self._ob}' (obsidian-headless) not found on PATH; "
                f"required for mode: sync"
            )
        if self.running:
            return
        # `ob sync --continuous` operates on the vault configured by `ob
        # sync-setup`, identified by its working directory — not a --vault flag.
        self._proc = subprocess.Popen(
            [self._ob, "sync", "--continuous"],
            cwd=str(self._config.vault_dir),
            stdout=sys.stderr,  # keep stdout clean for the stdio MCP channel
            stderr=sys.stderr,
        )

    def stop(self) -> None:
        if self._proc is None:
            return
        if self._proc.poll() is None:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self._proc.kill()
        self._proc = None
