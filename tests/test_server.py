"""Deny-by-default and capability separation at the tool-registration layer."""

from __future__ import annotations

from pathlib import Path

import pytest

from conftest import make_config
from fenced_obsidian_sync_mcp.server import build_server


def tool_names(config) -> set[str]:
    import asyncio

    mcp = build_server(config)
    return {t.name for t in asyncio.run(mcp.list_tools())}


def test_deny_all_registers_no_tools(vault: Path):
    """Posture: deny-all. An empty/all-disabled config exposes nothing."""
    assert tool_names(make_config(vault)) == set()


def test_create_only_registers_only_create(vault: Path):
    """Posture: create-only. Disabled capabilities are ABSENT, not merely guarded."""
    config = make_config(
        vault, capabilities={"create": {"enabled": True, "allow": ["Inbox/**"]}}
    )
    names = tool_names(config)
    assert names == {"create_note"}
    for absent in ("read_note", "list_notes", "update_note", "delete_note", "move_note"):
        assert absent not in names


def test_titles_only_exposes_no_content_tool(vault: Path):
    """Posture: titles-only. 'list' on, everything else off — no path to read bodies."""
    config = make_config(vault, capabilities={"list": {"enabled": True, "allow": ["**"]}})
    names = tool_names(config)
    assert names == {"list_notes"}
    # No registered tool can open file contents.
    assert "read_note" not in names
    assert "read_metadata" not in names
    assert "search_notes" not in names


@pytest.mark.parametrize(
    "cap,expected_tool",
    [
        ("list", "list_notes"),
        ("read_metadata", "read_metadata"),
        ("read", "read_note"),
        ("create", "create_note"),
        ("update", "update_note"),
        ("delete", "delete_note"),
        ("move", "move_note"),
    ],
)
def test_each_capability_registers_its_tool(vault: Path, cap: str, expected_tool: str):
    config = make_config(vault, capabilities={cap: {"enabled": True, "allow": ["**"]}})
    assert expected_tool in tool_names(config)
