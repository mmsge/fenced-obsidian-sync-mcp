"""Shared fixtures: a temporary vault plus config/fence/ops builders."""

from __future__ import annotations

from pathlib import Path

import pytest

from fenced_obsidian_sync_mcp import config as cfg
from fenced_obsidian_sync_mcp.audit import Audit
from fenced_obsidian_sync_mcp.fence import Fence
from fenced_obsidian_sync_mcp.ops import VaultOps


@pytest.fixture
def vault(tmp_path: Path) -> Path:
    """A small vault with Inbox/, Private/, and a couple of notes."""
    (tmp_path / "Inbox").mkdir()
    (tmp_path / "Private").mkdir()
    (tmp_path / "note.md").write_text("# hello\nbody text\n", encoding="utf-8")
    (tmp_path / "Private" / "secret.md").write_text("# secret\ntop secret\n", encoding="utf-8")
    return tmp_path


def make_config(vault: Path, **overrides) -> cfg.Config:
    data = {"mode": "local", "vault": str(vault), "collision": "fail", "capabilities": {}}
    data.update(overrides)
    return cfg.from_dict(data)


def make_ops(config: cfg.Config) -> VaultOps:
    fence = Fence(config)
    audit = Audit(config.audit)
    return VaultOps(config, fence, audit)
