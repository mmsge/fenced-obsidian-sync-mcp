"""Path confinement and glob policy — security invariant tests."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from conftest import make_config
from fenced_obsidian_sync_mcp.fence import CLIENT_MESSAGE, Fence, NotPermitted


def _fence(vault: Path) -> Fence:
    config = make_config(
        vault,
        capabilities={
            "read": {"enabled": True, "allow": ["**/*.md"], "deny": ["Private/**"]},
        },
    )
    return Fence(config)


# -- confinement: the traversal class ------------------------------------

@pytest.mark.parametrize(
    "bad",
    [
        "../outside.md",
        "../../etc/passwd",
        "Inbox/../../escape.md",
        "/etc/passwd",
        "/absolute.md",
        "sub\\..\\..\\win.md",  # backslash separators
        "",
    ],
)
def test_resolve_rejects_traversal_and_absolute(vault: Path, bad: str):
    with pytest.raises(NotPermitted):
        _fence(vault).resolve(bad)


@pytest.mark.parametrize(
    "encoded",
    [
        "..%2f..%2fetc%2fpasswd",      # percent-encoded slash
        "%2e%2e%2fescape.md",          # percent-encoded dots + slash
        "Inbox%2F..%2Fsecret.md",      # mixed case encoded slash
        "%252e%252e%252fescape.md",    # DOUBLE-encoded ../  (the CVE class)
        "note%2emd",                   # encoded dot anywhere
    ],
)
def test_resolve_rejects_encoded_separators(vault: Path, encoded: str):
    """Explicit regression for the percent-/double-encoded traversal CVE class."""
    with pytest.raises(NotPermitted):
        _fence(vault).resolve(encoded)


def test_resolve_rejects_escaping_symlink(vault: Path, tmp_path: Path):
    outside = tmp_path.parent / "outside_secret.txt"
    outside.write_text("secret", encoding="utf-8")
    link = vault / "escape_link.md"
    os.symlink(outside, link)
    with pytest.raises(NotPermitted):
        _fence(vault).resolve("escape_link.md")


def test_resolve_allows_normal_path(vault: Path):
    abs_path, rel = _fence(vault).resolve("Inbox/note.md")
    assert rel == "Inbox/note.md"
    assert str(abs_path).endswith("Inbox/note.md")


# -- policy: deny-wins ----------------------------------------------------

def test_deny_overrides_allow_on_every_capability(vault: Path):
    config = make_config(
        vault,
        capabilities={
            "read": {"enabled": True, "allow": ["**/*.md"], "deny": ["Private/**"]},
            "list": {"enabled": True, "allow": ["**"], "deny": ["Private/**"]},
        },
    )
    fence = Fence(config)
    # Allowed by '**' but denied by 'Private/**' -> deny wins, on each capability.
    assert fence.permit("read", "Private/secret.md") is False
    assert fence.permit("list", "Private/secret.md") is False
    # A non-denied path is still permitted.
    assert fence.permit("read", "note.md") is True


def test_disabled_capability_permits_nothing(vault: Path):
    config = make_config(vault, capabilities={"read": {"enabled": False}})
    fence = Fence(config)
    assert fence.permit("read", "note.md") is False


# -- no existence oracle --------------------------------------------------

def test_denied_message_is_uniform_for_existing_and_missing(vault: Path):
    fence = _fence(vault)
    # 'Private/secret.md' exists but is denied; 'Private/ghost.md' does not exist.
    with pytest.raises(NotPermitted) as e_exist:
        fence.check("read", "Private/secret.md")
    with pytest.raises(NotPermitted) as e_missing:
        fence.check("read", "Private/ghost.md")
    assert str(e_exist.value) == str(e_missing.value) == CLIENT_MESSAGE
