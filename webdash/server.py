"""
webdash/server.py — FastAPI app factory + uvicorn launcher.

Binds all interfaces (0.0.0.0) so private-network operators can reach the
console. The network boundary is enforced by PrivateClientMiddleware: every
request's peer IP must be RFC1918-private or loopback, else 403 — applied
ahead of bearer-token auth, which remains the primary auth boundary. Serves
the built frontend (webdash/static) at / when present, the API under /api,
and the WebSocket feed at /api/stream. OpenAPI/docs disabled to keep the
control surface quiet.
"""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI

from webdash.api import control, models, monitor, n8n
from webdash.net_guard import PrivateClientMiddleware
from webdash.stream import stream_endpoint

# SPA and API are same-origin (prod: static mount; dev: vite proxies /api), so no CORS needed.
_STATIC_DIR = Path(__file__).parent / "static"


def create_app() -> FastAPI:
    app = FastAPI(
        title="OpenElia Dashboard",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )

    # Network gate: reject non-RFC1918/non-loopback peers with 403 before any
    # route or auth runs. Outermost middleware = first to see every request.
    app.add_middleware(PrivateClientMiddleware)

    app.include_router(monitor.router)
    app.include_router(models.router)
    app.include_router(control.router)
    app.include_router(n8n.router)
    app.add_api_websocket_route("/api/stream", stream_endpoint)

    @app.get("/healthz")
    def healthz() -> dict:  # unauthenticated liveness probe
        return {"ok": True}

    if _STATIC_DIR.exists():
        from fastapi.staticfiles import StaticFiles

        app.mount("/", StaticFiles(directory=str(_STATIC_DIR), html=True), name="static")

    return app


app = create_app()


def _banner(host: str, port: int) -> None:
    from webdash.security import get_or_create_token

    token = get_or_create_token()
    loopback = host in ("127.0.0.1", "localhost", "::1")
    if not loopback:
        print("\n  ⚠  LAN-EXPOSED: dashboard bound to "
              f"{host} — reachable from the whole private network.\n"
              "     Peer IP must be RFC1918/loopback (403 otherwise), and the\n"
              "     bearer token is the only auth boundary. The #token in the\n"
              "     URL below is LAN-reachable — do not share it or leave it in\n"
              "     browser history on a shared box.")
    print("\n  OpenElia dashboard →  "
          f"http://{host}:{port}/#token={token}\n"
          "  (token also required as 'Authorization: Bearer <token>' for /api)\n")


async def serve(host: str = "0.0.0.0", port: int = 8765) -> None:  # nosec B104 — LAN-exposed by design; PrivateClientMiddleware gates peers
    """Async launcher — runs inside an existing event loop (e.g. main.py's asyncio.run)."""
    import uvicorn

    _banner(host, port)
    config = uvicorn.Config(app, host=host, port=port, log_level="info")
    await uvicorn.Server(config).serve()


def run(host: str = "0.0.0.0", port: int = 8765) -> None:  # nosec B104 — LAN-exposed by design; PrivateClientMiddleware gates peers
    """Sync launcher for standalone use (no running event loop)."""
    import asyncio

    asyncio.run(serve(host, port))
