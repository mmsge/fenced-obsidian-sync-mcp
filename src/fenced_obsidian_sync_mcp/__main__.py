"""CLI entrypoint: load config, optionally start sync, serve over stdio or HTTP."""

from __future__ import annotations

import argparse
import sys

from . import __version__
from .config import ConfigError, load
from .server import build_server


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="fenced-obsidian-sync-mcp",
        description="A deny-by-default, finely fenced MCP server over an Obsidian vault.",
    )
    parser.add_argument("-c", "--config", required=True, help="path to the YAML config file")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    args = parser.parse_args(argv)

    try:
        config = load(args.config)
    except (ConfigError, OSError) as exc:
        print(f"config error: {exc}", file=sys.stderr)
        return 2

    enabled = [name for name, cap in config.capabilities.items() if cap.enabled]
    print(
        f"fenced-obsidian-sync-mcp: mode={config.mode} vault={config.vault_dir} "
        f"capabilities={enabled or '(none — dark vault)'}",
        file=sys.stderr,
    )

    sync_manager = None
    if config.mode == "sync":
        from .sync import SyncManager

        sync_manager = SyncManager(config)
        sync_manager.start()

    mcp = build_server(config)
    try:
        if config.transport.type == "http":
            from .http import run_http

            run_http(mcp, config)
        else:
            mcp.run(transport="stdio")
    finally:
        if sync_manager is not None:
            sync_manager.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
