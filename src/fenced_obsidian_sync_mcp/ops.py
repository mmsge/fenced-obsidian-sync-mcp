"""Vault operations, each gated by the fence.

Every operation authorizes through :class:`~fenced_obsidian_sync_mcp.fence.Fence`
before touching the filesystem, and records the decision to the audit log. Each
capability does *only* its own job: ``list`` performs ``scandir`` and never opens
a file; ``create`` only ever creates and never overwrites.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from .audit import Audit
from .config import Config
from .fence import Fence, NotPermitted

# Files/dirs that are vault plumbing, never content. Skipped by list/search even
# if a permissive glob would otherwise match.
_SKIP_DIRS = {".obsidian", ".trash", ".git"}


@dataclass
class SearchHit:
    path: str
    line: int
    snippet: str


class VaultOps:
    def __init__(self, config: Config, fence: Fence, audit: Audit) -> None:
        self._config = config
        self._fence = fence
        self._audit = audit

    # -- authorization helper ---------------------------------------------

    def _authorize(self, capability: str, user_path: str) -> tuple[Path, str]:
        try:
            abs_path, rel = self._fence.check(capability, user_path)
        except NotPermitted as exc:
            self._audit.deny(capability, user_path, exc.reason)
            raise
        self._audit.allow(capability, rel)
        return abs_path, rel

    # -- list: readdir only, never opens a file ---------------------------

    def list(self, subdir: str = "") -> list[str]:
        # Confine the starting directory (no policy check on the dir itself).
        if subdir:
            try:
                start, _ = self._fence.resolve(subdir)
            except NotPermitted as exc:
                self._audit.deny("list", subdir, exc.reason)
                raise
        else:
            start = self._fence.root

        results: list[str] = []
        # followlinks=False: os.walk will not traverse symlinked directories, so
        # listing cannot escape the root via a directory symlink.
        for dirpath, dirnames, filenames in os.walk(start, followlinks=False):
            dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
            for name in filenames:
                rel = os.path.relpath(os.path.join(dirpath, name), self._fence.root)
                rel = Path(rel).as_posix()
                if self._fence.permit("list", rel):
                    results.append(rel)
        self._audit.allow("list", subdir or ".")
        return sorted(results)

    # -- read_metadata: frontmatter + stat only ---------------------------

    def read_metadata(self, path: str) -> dict:
        abs_path, rel = self._authorize("read_metadata", path)
        if not abs_path.is_file():
            raise FileNotFoundError(f"no such note: {rel}")
        frontmatter = _parse_frontmatter(abs_path)
        st = abs_path.stat()
        tags = frontmatter.get("tags", [])
        if isinstance(tags, str):
            tags = [tags]
        return {
            "path": rel,
            "frontmatter": frontmatter,
            "tags": tags,
            "size": st.st_size,
            "modified": st.st_mtime,
        }

    # -- read: full contents ----------------------------------------------

    def read(self, path: str) -> str:
        abs_path, rel = self._authorize("read", path)
        if not abs_path.is_file():
            raise FileNotFoundError(f"no such note: {rel}")
        return abs_path.read_text(encoding="utf-8")

    # -- search: content search (implies read) ----------------------------

    def search(self, query: str, limit: int = 50) -> list[SearchHit]:
        hits: list[SearchHit] = []
        needle = query.lower()
        for dirpath, dirnames, filenames in os.walk(self._fence.root, followlinks=False):
            dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
            for name in filenames:
                rel = Path(
                    os.path.relpath(os.path.join(dirpath, name), self._fence.root)
                ).as_posix()
                if not self._fence.permit("search", rel):
                    continue
                try:
                    text = Path(dirpath, name).read_text(encoding="utf-8")
                except (UnicodeDecodeError, OSError):
                    continue
                for lineno, line in enumerate(text.splitlines(), start=1):
                    if needle in line.lower():
                        hits.append(SearchHit(path=rel, line=lineno, snippet=line.strip()[:200]))
                        if len(hits) >= limit:
                            self._audit.allow("search", query)
                            return hits
        self._audit.allow("search", query)
        return hits

    # -- create: atomic, exclusive, never overwrites ----------------------

    def create(self, path: str, content: str = "") -> str:
        abs_path, rel = self._authorize("create", path)
        target = abs_path
        if self._config.collision == "suffix":
            target = _next_free(abs_path)
        # Confine the (possibly suffixed) parent and create it within the root.
        os.makedirs(target.parent, exist_ok=True)
        try:
            # O_EXCL: the create fails if the path already exists. No overwrite is
            # possible, even under a race.
            fd = os.open(target, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
        except FileExistsError as exc:
            raise FileExistsError(f"refusing to overwrite existing note: {rel}") from exc
        try:
            os.write(fd, content.encode("utf-8"))
        finally:
            os.close(fd)
        return Path(os.path.relpath(target, self._fence.root)).as_posix()

    # -- update: modify or append existing files --------------------------

    def update(self, path: str, content: str, append: bool = False) -> str:
        abs_path, rel = self._authorize("update", path)
        if not abs_path.is_file():
            raise FileNotFoundError(f"no such note to update: {rel}")
        mode = "a" if append else "w"
        with abs_path.open(mode, encoding="utf-8") as fh:
            fh.write(content)
        return rel

    # -- delete -----------------------------------------------------------

    def delete(self, path: str) -> str:
        abs_path, rel = self._authorize("delete", path)
        if not abs_path.is_file():
            raise FileNotFoundError(f"no such note to delete: {rel}")
        os.remove(abs_path)
        return rel

    # -- move: rename/relocate, never overwrites --------------------------

    def move(self, src: str, dst: str) -> str:
        src_abs, src_rel = self._authorize("move", src)
        dst_abs, dst_rel = self._authorize("move", dst)
        if not src_abs.is_file():
            raise FileNotFoundError(f"no such note to move: {src_rel}")
        if dst_abs.exists():
            raise FileExistsError(f"refusing to overwrite existing note: {dst_rel}")
        os.makedirs(dst_abs.parent, exist_ok=True)
        os.rename(src_abs, dst_abs)
        return dst_rel


def _next_free(path: Path) -> Path:
    """Return ``path`` or the first ``stem N.ext`` that does not yet exist."""
    if not path.exists():
        return path
    stem, suffix = path.stem, path.suffix
    n = 1
    while True:
        candidate = path.with_name(f"{stem} {n}{suffix}")
        if not candidate.exists():
            return candidate
        n += 1


def _parse_frontmatter(path: Path) -> dict:
    """Parse a leading YAML frontmatter block (``---`` ... ``---``). Best-effort."""
    import yaml

    text = path.read_text(encoding="utf-8")
    if not text.startswith("---"):
        return {}
    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        return {}
    for i in range(1, len(lines)):
        if lines[i].strip() == "---":
            block = "\n".join(lines[1:i])
            try:
                data = yaml.safe_load(block)
            except yaml.YAMLError:
                return {}
            return data if isinstance(data, dict) else {}
    return {}
