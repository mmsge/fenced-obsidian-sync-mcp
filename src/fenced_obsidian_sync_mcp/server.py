"""MCP server assembly: register *only* the tools for enabled capabilities.

Deny-by-default is enforced structurally here. A disabled capability's tool is
never passed to ``@mcp.tool`` — there is no guarded surface to bypass, because
there is no surface at all. ``build_server(config).list_tools()`` is the proof:
a disabled capability is absent from it.
"""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from .audit import Audit
from .config import Config
from .fence import CLIENT_MESSAGE, Fence, NotPermitted
from .ops import VaultOps


def build_server(config: Config, name: str = "fenced-obsidian-sync-mcp") -> FastMCP:
    fence = Fence(config)
    audit = Audit(config.audit)
    ops = VaultOps(config, fence, audit)

    settings = {}
    if config.transport.type == "http":
        settings = {"host": config.transport.host, "port": config.transport.port}
    mcp = FastMCP(name, **settings)

    def _guard(exc: Exception) -> Exception:
        # Collapse any fence denial to the uniform client message so a denied
        # path never reveals whether the file exists.
        if isinstance(exc, NotPermitted):
            return ValueError(CLIENT_MESSAGE)
        return exc

    if config.enabled("list"):

        @mcp.tool(description="Enumerate note paths within the fenced scope (paths only).")
        def list_notes(subdir: str = "") -> list[str]:
            try:
                return ops.list(subdir)
            except NotPermitted as exc:
                raise _guard(exc) from None

    if config.enabled("read_metadata"):

        @mcp.tool(description="Read a note's frontmatter, tags, and stat — not its body.")
        def read_metadata(path: str) -> dict:
            try:
                return ops.read_metadata(path)
            except NotPermitted as exc:
                raise _guard(exc) from None

    if config.enabled("read"):

        @mcp.tool(description="Read the full contents of a note.")
        def read_note(path: str) -> str:
            try:
                return ops.read(path)
            except NotPermitted as exc:
                raise _guard(exc) from None

    if config.enabled("search"):

        @mcp.tool(description="Search note contents (implies read) and return matching snippets.")
        def search_notes(query: str, limit: int = 50) -> list[dict]:
            try:
                return [hit.__dict__ for hit in ops.search(query, limit)]
            except NotPermitted as exc:
                raise _guard(exc) from None

    if config.enabled("create"):

        @mcp.tool(description="Create a new note. Never overwrites an existing file.")
        def create_note(path: str, content: str = "") -> str:
            try:
                return ops.create(path, content)
            except NotPermitted as exc:
                raise _guard(exc) from None

    if config.enabled("update"):

        @mcp.tool(description="Update (overwrite or append) an existing note.")
        def update_note(path: str, content: str, append: bool = False) -> str:
            try:
                return ops.update(path, content, append)
            except NotPermitted as exc:
                raise _guard(exc) from None

    if config.enabled("delete"):

        @mcp.tool(description="Delete an existing note.")
        def delete_note(path: str) -> str:
            try:
                return ops.delete(path)
            except NotPermitted as exc:
                raise _guard(exc) from None

    if config.enabled("move"):

        @mcp.tool(description="Move/rename a note. Never overwrites an existing file.")
        def move_note(src: str, dst: str) -> str:
            try:
                return ops.move(src, dst)
            except NotPermitted as exc:
                raise _guard(exc) from None

    return mcp
