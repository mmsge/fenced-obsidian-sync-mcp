"""The fence: path confinement and glob-scoped capability permission.

This is the security core. Every path that reaches the filesystem passes through
:meth:`Fence.resolve` (confinement) and :meth:`Fence.permit` (policy). A denial
of either raises :class:`NotPermitted`, whose client-facing message is always the
uniform ``"not permitted"`` so that denied paths reveal nothing about whether a
file exists (no existence oracle).
"""

from __future__ import annotations

import os
import re
from pathlib import Path, PurePosixPath

from wcmatch import glob as wcglob

from .config import Capability, Config

CLIENT_MESSAGE = "not permitted"

# wcmatch flags: GLOBSTAR makes ``**`` span directories; case-sensitive (the
# default on POSIX). Dotfiles are NOT matched by ``*``/``**`` unless a pattern
# names the leading dot, which keeps ``.obsidian/**`` out of ``**/*.md``.
_GLOB_FLAGS = wcglob.GLOBSTAR

# Any percent sign is rejected outright. This is a deliberate superset of the
# spec requirement (reject percent-/double-encoded separators like ``%2f``,
# ``%2e``, ``%5c`` and double-encoded ``%252f``): vault paths have no legitimate
# need for ``%``, and a blanket rejection cannot be bypassed by novel encodings.
_PERCENT = re.compile(r"%")


class NotPermitted(Exception):
    """A path is outside the fence or denied by policy.

    The string form is always the uniform client message. The internal
    ``reason`` carries the real cause for the audit log only.
    """

    def __init__(self, reason: str) -> None:
        super().__init__(CLIENT_MESSAGE)
        self.reason = reason

    def __str__(self) -> str:  # never leak the reason to clients
        return CLIENT_MESSAGE


def _match(path: str, patterns: tuple[str, ...]) -> bool:
    if not patterns:
        return False
    return wcglob.globmatch(path, list(patterns), flags=_GLOB_FLAGS)


class Fence:
    """Confines paths to the vault root and applies per-capability glob policy."""

    def __init__(self, config: Config) -> None:
        self._config = config
        # Canonical, symlink-resolved root. All resolved paths must live under it.
        self.root = Path(os.path.realpath(config.vault_dir))

    # -- confinement -------------------------------------------------------

    def resolve(self, user_path: str) -> tuple[Path, str]:
        """Confine ``user_path`` to the vault root.

        Returns ``(absolute_path, relative_posix_path)``. Raises
        :class:`NotPermitted` for any escape attempt: encoded separators,
        backslashes, absolute paths, ``..`` segments, or a real path (after
        symlink resolution) outside the root.
        """
        if not isinstance(user_path, str) or user_path == "":
            raise NotPermitted("empty or non-string path")

        # Reject encodings before any interpretation. Defeats %2e%2e%2f and the
        # double-encoded %252e..%252f traversal class (a real CVE in comparable
        # Obsidian MCP tools).
        if _PERCENT.search(user_path):
            raise NotPermitted(f"percent-encoded path rejected: {user_path!r}")

        # Backslashes are not valid Obsidian separators and invite Windows-style
        # traversal confusion; reject them outright.
        if "\\" in user_path:
            raise NotPermitted(f"backslash in path rejected: {user_path!r}")

        if user_path.startswith("/") or PurePosixPath(user_path).is_absolute():
            raise NotPermitted(f"absolute path rejected: {user_path!r}")

        parts = PurePosixPath(user_path).parts
        if any(part == ".." for part in parts):
            raise NotPermitted(f"parent-directory segment rejected: {user_path!r}")

        rel = PurePosixPath(*[p for p in parts if p not in (".",)])
        candidate = self.root / Path(*rel.parts)
        real = Path(os.path.realpath(candidate))

        # Symlink-escape check: the real path must be the root or under it.
        if real != self.root and self.root not in real.parents:
            raise NotPermitted(f"path escapes vault root: {user_path!r}")

        return real, rel.as_posix()

    # -- policy ------------------------------------------------------------

    def _capability(self, name: str) -> Capability:
        return self._config.capabilities[name]

    def permit(self, capability: str, rel_path: str) -> bool:
        """Return whether ``capability`` permits ``rel_path`` (deny wins over allow)."""
        cap = self._capability(capability)
        if not cap.enabled:
            return False
        if _match(rel_path, cap.deny):
            return False
        return _match(rel_path, cap.allow)

    def check(self, capability: str, user_path: str) -> tuple[Path, str]:
        """Confine then authorize. Raises uniform :class:`NotPermitted` on any failure.

        Confinement runs first, but both confinement and policy denials raise the
        same exception type with the same client message — no existence oracle.
        """
        abs_path, rel = self.resolve(user_path)
        if not self.permit(capability, rel):
            raise NotPermitted(f"capability '{capability}' denies {rel!r}")
        return abs_path, rel
