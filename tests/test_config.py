"""Config validation and deny-by-default defaults."""

from __future__ import annotations

from pathlib import Path

import pytest

from conftest import make_config
from fenced_obsidian_sync_mcp import config as cfg


def test_empty_capabilities_are_all_disabled(vault: Path):
    config = make_config(vault)
    assert all(not c.enabled for c in config.capabilities.values())
    assert config.enabled("read") is False
    # The full closed set is present, every one disabled (deny-by-default).
    assert set(config.capabilities) == set(cfg.CAPABILITIES)


def test_unknown_capability_is_rejected(vault: Path):
    with pytest.raises(cfg.ConfigError):
        make_config(vault, capabilities={"raed": {"enabled": True, "allow": ["**"]}})


def test_enabled_capability_requires_allow(vault: Path):
    with pytest.raises(cfg.ConfigError):
        make_config(vault, capabilities={"read": {"enabled": True}})


def test_search_implies_read(vault: Path):
    with pytest.raises(cfg.ConfigError):
        make_config(
            vault,
            capabilities={"search": {"enabled": True, "allow": ["**/*.md"]}},
        )
    # With read also enabled it validates.
    config = make_config(
        vault,
        capabilities={
            "read": {"enabled": True, "allow": ["**/*.md"]},
            "search": {"enabled": True, "allow": ["**/*.md"]},
        },
    )
    assert config.enabled("search")


@pytest.mark.parametrize("bad", [{"mode": "weird"}, {"collision": "clobber"}])
def test_invalid_enum_values_rejected(vault: Path, bad: dict):
    with pytest.raises(cfg.ConfigError):
        make_config(vault, **bad)


def test_vault_is_required(tmp_path: Path):
    with pytest.raises(cfg.ConfigError):
        cfg.from_dict({"mode": "local"})


def test_http_requires_bearer_token(vault: Path):
    with pytest.raises(cfg.ConfigError):
        make_config(
            vault,
            capabilities={"list": {"enabled": True, "allow": ["**"]}},
            transport={"type": "http"},
        )


def test_bearer_token_from_env(vault: Path, monkeypatch):
    monkeypatch.setenv("FOSM_TOKEN", "s3cret-from-env")
    config = make_config(
        vault,
        capabilities={"list": {"enabled": True, "allow": ["**"]}},
        transport={"type": "http", "auth": {"bearer_token_env": "FOSM_TOKEN"}},
    )
    assert config.transport.auth.bearer_token == "s3cret-from-env"


def test_bearer_token_env_unset_is_rejected(vault: Path, monkeypatch):
    monkeypatch.delenv("FOSM_MISSING", raising=False)
    with pytest.raises(cfg.ConfigError):
        make_config(
            vault,
            capabilities={"list": {"enabled": True, "allow": ["**"]}},
            transport={"type": "http", "auth": {"bearer_token_env": "FOSM_MISSING"}},
        )
