"""Configuration loading and validation.

A config is a single declarative YAML file. Deny-by-default is enforced here:
any capability not explicitly ``enabled: true`` is disabled, and a disabled
capability's tool is never registered by the server.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

import yaml

# The complete, closed set of capabilities. A capability outside this set in a
# config is a typo and is rejected rather than silently ignored.
CAPABILITIES: tuple[str, ...] = (
    "list",
    "read_metadata",
    "read",
    "search",
    "create",
    "update",
    "delete",
    "move",
)

MODES = ("local", "sync")
COLLISIONS = ("fail", "suffix")
TRANSPORTS = ("stdio", "http")


class ConfigError(ValueError):
    """Raised when a configuration file is malformed or internally inconsistent."""


@dataclass(frozen=True)
class Capability:
    """One capability's enablement and path-glob scoping.

    ``allow``/``deny`` are wcmatch GLOBSTAR globs evaluated against vault-relative
    POSIX paths. ``deny`` always wins (see :mod:`fence`).
    """

    name: str
    enabled: bool = False
    allow: tuple[str, ...] = ()
    deny: tuple[str, ...] = ()


@dataclass(frozen=True)
class AuthConfig:
    bearer_token: str | None = None


@dataclass(frozen=True)
class TLSConfig:
    certfile: str | None = None
    keyfile: str | None = None


@dataclass(frozen=True)
class TransportConfig:
    type: str = "stdio"
    host: str = "127.0.0.1"
    port: int = 8080
    tls: TLSConfig = field(default_factory=TLSConfig)
    auth: AuthConfig = field(default_factory=AuthConfig)


@dataclass(frozen=True)
class AuditConfig:
    enabled: bool = False
    path: str | None = None


@dataclass(frozen=True)
class Config:
    mode: str
    vault: str
    vault_dir: Path
    collision: str
    capabilities: dict[str, Capability]
    transport: TransportConfig
    audit: AuditConfig

    def enabled(self, name: str) -> bool:
        cap = self.capabilities.get(name)
        return bool(cap and cap.enabled)


def _capability(name: str, raw: object) -> Capability:
    if raw is None:
        return Capability(name=name, enabled=False)
    if not isinstance(raw, dict):
        raise ConfigError(f"capability '{name}' must be a mapping")
    unknown = set(raw) - {"enabled", "allow", "deny"}
    if unknown:
        raise ConfigError(f"capability '{name}' has unknown keys: {sorted(unknown)}")

    enabled = bool(raw.get("enabled", False))
    allow = tuple(raw.get("allow", ()) or ())
    deny = tuple(raw.get("deny", ()) or ())

    for label, globs in (("allow", allow), ("deny", deny)):
        if not all(isinstance(g, str) for g in globs):
            raise ConfigError(f"capability '{name}' {label} globs must be strings")

    # An enabled capability with no allow list permits nothing, which is almost
    # certainly an operator mistake. Fail loudly rather than silently no-op.
    if enabled and not allow:
        raise ConfigError(
            f"capability '{name}' is enabled but has an empty 'allow' list; "
            f"it would permit nothing"
        )

    return Capability(name=name, enabled=enabled, allow=allow, deny=deny)


def _transport(raw: object) -> TransportConfig:
    if raw is None:
        return TransportConfig()
    if not isinstance(raw, dict):
        raise ConfigError("'transport' must be a mapping")
    ttype = raw.get("type", "stdio")
    if ttype not in TRANSPORTS:
        raise ConfigError(f"transport.type must be one of {TRANSPORTS}, got {ttype!r}")

    tls_raw = raw.get("tls") or {}
    auth_raw = raw.get("auth") or {}
    tls = TLSConfig(certfile=tls_raw.get("certfile"), keyfile=tls_raw.get("keyfile"))

    # The token may be given inline (`bearer_token`) or, preferably for
    # deployment, sourced from an environment variable (`bearer_token_env`) so
    # the secret never lives in the config file. Inline wins if both are set.
    token = auth_raw.get("bearer_token")
    token_env = auth_raw.get("bearer_token_env")
    if not token and token_env:
        token = os.environ.get(token_env)
        if not token:
            raise ConfigError(
                f"transport.auth.bearer_token_env points at ${token_env}, "
                f"which is unset or empty"
            )
    auth = AuthConfig(bearer_token=token)

    return TransportConfig(
        type=ttype,
        host=raw.get("host", "127.0.0.1"),
        port=int(raw.get("port", 8080)),
        tls=tls,
        auth=auth,
    )


def _audit(raw: object) -> AuditConfig:
    if raw is None:
        return AuditConfig()
    if not isinstance(raw, dict):
        raise ConfigError("'audit' must be a mapping")
    return AuditConfig(enabled=bool(raw.get("enabled", False)), path=raw.get("path"))


def from_dict(data: dict, *, base_dir: Path | None = None) -> Config:
    """Validate a raw config mapping into a :class:`Config`.

    ``base_dir`` is the directory the config file lives in; relative vault paths
    resolve against it.
    """
    if not isinstance(data, dict):
        raise ConfigError("config root must be a mapping")

    mode = data.get("mode", "local")
    if mode not in MODES:
        raise ConfigError(f"mode must be one of {MODES}, got {mode!r}")

    vault = data.get("vault")
    if not vault or not isinstance(vault, str):
        raise ConfigError("'vault' is required (a directory path for local, a vault name for sync)")

    collision = data.get("collision", "fail")
    if collision not in COLLISIONS:
        raise ConfigError(f"collision must be one of {COLLISIONS}, got {collision!r}")

    # Where the notes actually live on disk.
    #  - local: 'vault' IS the directory.
    #  - sync:  'vault' is the remote vault name; 'vault_dir' (or a default) is
    #           the local directory obsidian-headless syncs into.
    base = base_dir or Path.cwd()
    if mode == "local":
        vault_dir = Path(vault)
    else:
        vault_dir_raw = data.get("vault_dir")
        vault_dir = Path(vault_dir_raw) if vault_dir_raw else (Path.home() / "vaults" / vault)
    if not vault_dir.is_absolute():
        vault_dir = (base / vault_dir).resolve()

    caps_raw = data.get("capabilities") or {}
    if not isinstance(caps_raw, dict):
        raise ConfigError("'capabilities' must be a mapping")
    unknown_caps = set(caps_raw) - set(CAPABILITIES)
    if unknown_caps:
        raise ConfigError(f"unknown capabilities: {sorted(unknown_caps)}")

    capabilities = {name: _capability(name, caps_raw.get(name)) for name in CAPABILITIES}

    # search implies read: snippets would otherwise be a content oracle when read
    # is off. Enforce the dependency explicitly rather than silently.
    if capabilities["search"].enabled and not capabilities["read"].enabled:
        raise ConfigError("capability 'search' implies 'read'; enable 'read' as well")

    transport = _transport(data.get("transport"))
    audit = _audit(data.get("audit"))

    if transport.type == "http" and not transport.auth.bearer_token:
        raise ConfigError("transport.type 'http' requires transport.auth.bearer_token")

    return Config(
        mode=mode,
        vault=vault,
        vault_dir=vault_dir,
        collision=collision,
        capabilities=capabilities,
        transport=transport,
        audit=audit,
    )


def load(path: str | Path) -> Config:
    """Load and validate a YAML config file."""
    p = Path(path)
    with p.open("r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    return from_dict(data, base_dir=p.resolve().parent)
