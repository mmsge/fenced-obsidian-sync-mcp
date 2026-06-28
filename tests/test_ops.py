"""Vault operation behaviour: atomic create, capability separation, no oracle."""

from __future__ import annotations

import builtins
from pathlib import Path

import pytest

from conftest import make_config, make_ops
from fenced_obsidian_sync_mcp.fence import CLIENT_MESSAGE, NotPermitted

# -- atomic, no-overwrite create -----------------------------------------

def test_create_in_allowed_path(vault: Path):
    config = make_config(vault, capabilities={"create": {"enabled": True, "allow": ["Inbox/**"]}})
    ops = make_ops(config)
    rel = ops.create("Inbox/new.md", "hello")
    assert rel == "Inbox/new.md"
    assert (vault / "Inbox" / "new.md").read_text() == "hello"


def test_create_outside_allow_is_refused(vault: Path):
    config = make_config(vault, capabilities={"create": {"enabled": True, "allow": ["Inbox/**"]}})
    ops = make_ops(config)
    with pytest.raises(NotPermitted):
        ops.create("Outbox/new.md", "x")


def test_create_collision_fail_never_overwrites(vault: Path):
    config = make_config(
        vault,
        collision="fail",
        capabilities={"create": {"enabled": True, "allow": ["**/*.md"]}},
    )
    ops = make_ops(config)
    (vault / "Inbox" / "dup.md").write_text("ORIGINAL")
    with pytest.raises(FileExistsError):
        ops.create("Inbox/dup.md", "NEW")
    # Original bytes are intact — O_EXCL guaranteed no clobber.
    assert (vault / "Inbox" / "dup.md").read_text() == "ORIGINAL"


def test_create_collision_suffix_lands_new_file(vault: Path):
    config = make_config(
        vault,
        collision="suffix",
        capabilities={"create": {"enabled": True, "allow": ["**/*.md"]}},
    )
    ops = make_ops(config)
    (vault / "Inbox" / "dup.md").write_text("ORIGINAL")
    rel = ops.create("Inbox/dup.md", "NEW")
    assert rel == "Inbox/dup 1.md"
    assert (vault / "Inbox" / "dup.md").read_text() == "ORIGINAL"  # untouched
    assert (vault / "Inbox" / "dup 1.md").read_text() == "NEW"


# -- capability separation: list does readdir only -----------------------

def test_list_returns_paths_within_allow(vault: Path):
    config = make_config(
        vault,
        capabilities={"list": {"enabled": True, "allow": ["**/*.md"], "deny": ["Private/**"]}},
    )
    ops = make_ops(config)
    listed = ops.list()
    assert "note.md" in listed
    assert "Private/secret.md" not in listed  # denied subtree never surfaces


def test_list_never_opens_file_contents(vault: Path, monkeypatch):
    config = make_config(vault, capabilities={"list": {"enabled": True, "allow": ["**"]}})
    ops = make_ops(config)

    def _boom(*a, **k):
        raise AssertionError("list opened a file — it must readdir only")

    monkeypatch.setattr(builtins, "open", _boom)
    monkeypatch.setattr(Path, "read_text", lambda *a, **k: _boom())
    # Must succeed without opening any file.
    assert "note.md" in ops.list()


# -- read / search --------------------------------------------------------

def test_read_returns_contents(vault: Path):
    config = make_config(vault, capabilities={"read": {"enabled": True, "allow": ["**/*.md"]}})
    ops = make_ops(config)
    assert "body text" in ops.read("note.md")


def test_search_respects_deny(vault: Path):
    config = make_config(
        vault,
        capabilities={
            "read": {"enabled": True, "allow": ["**/*.md"]},
            "search": {"enabled": True, "allow": ["**/*.md"], "deny": ["Private/**"]},
        },
    )
    ops = make_ops(config)
    hits = ops.search("secret")
    # 'Private/secret.md' contains 'secret' but is denied -> no hit from it.
    assert all(h.path != "Private/secret.md" for h in hits)


# -- no existence oracle at the op layer ---------------------------------

def test_denied_read_uniform_regardless_of_existence(vault: Path):
    config = make_config(
        vault,
        capabilities={"read": {"enabled": True, "allow": ["**/*.md"], "deny": ["Private/**"]}},
    )
    ops = make_ops(config)
    with pytest.raises(NotPermitted) as e1:
        ops.read("Private/secret.md")   # exists, denied
    with pytest.raises(NotPermitted) as e2:
        ops.read("Private/ghost.md")    # missing, denied
    assert str(e1.value) == str(e2.value) == CLIENT_MESSAGE


# -- update / delete / move ----------------------------------------------

def test_update_append(vault: Path):
    config = make_config(vault, capabilities={"update": {"enabled": True, "allow": ["**/*.md"]}})
    ops = make_ops(config)
    ops.update("note.md", "\nmore", append=True)
    assert "more" in (vault / "note.md").read_text()


def test_delete(vault: Path):
    config = make_config(vault, capabilities={"delete": {"enabled": True, "allow": ["Inbox/**"]}})
    ops = make_ops(config)
    (vault / "Inbox" / "x.md").write_text("y")
    ops.delete("Inbox/x.md")
    assert not (vault / "Inbox" / "x.md").exists()


def test_move_never_overwrites(vault: Path):
    config = make_config(vault, capabilities={"move": {"enabled": True, "allow": ["**/*.md"]}})
    ops = make_ops(config)
    (vault / "Inbox" / "a.md").write_text("A")
    (vault / "Inbox" / "b.md").write_text("B")
    with pytest.raises(FileExistsError):
        ops.move("Inbox/a.md", "Inbox/b.md")
    assert (vault / "Inbox" / "b.md").read_text() == "B"
