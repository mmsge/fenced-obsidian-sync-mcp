"""HTTP transport: streamable-http behind bearer-token auth and TLS.

TLS may be terminated here (pass certfile/keyfile) or by a reverse proxy such as
Caddy. Bearer-token auth is enforced in-process regardless. Full OAuth is a
future extension; bearer + TLS is the supported remote posture today.
"""

from __future__ import annotations

import hmac

from mcp.server.fastmcp import FastMCP
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from .config import Config


class BearerAuthMiddleware:
    """Reject any request lacking a valid ``Authorization: Bearer <token>`` header."""

    def __init__(self, app: ASGIApp, token: str) -> None:
        self._app = app
        self._token = token

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return
        request = Request(scope, receive=receive)
        header = request.headers.get("authorization", "")
        prefix = "Bearer "
        ok = header.startswith(prefix) and hmac.compare_digest(header[len(prefix) :], self._token)
        if not ok:
            response = JSONResponse({"error": "unauthorized"}, status_code=401)
            await response(scope, receive, send)
            return
        await self._app(scope, receive, send)


def build_http_app(mcp: FastMCP, config: Config):
    """Return an ASGI app for the MCP server wrapped in bearer auth."""
    token = config.transport.auth.bearer_token
    if not token:
        raise ValueError("http transport requires transport.auth.bearer_token")
    app = mcp.streamable_http_app()
    return BearerAuthMiddleware(app, token)


def run_http(mcp: FastMCP, config: Config) -> None:
    import uvicorn

    app = build_http_app(mcp, config)
    tls = config.transport.tls
    uvicorn.run(
        app,
        host=config.transport.host,
        port=config.transport.port,
        ssl_certfile=tls.certfile,
        ssl_keyfile=tls.keyfile,
    )
