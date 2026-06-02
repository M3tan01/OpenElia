"""
webdash/server.py — FastAPI app factory + uvicorn launcher.

Binds 127.0.0.1 only. Serves the built frontend (webdash/static) at / when present,
the API under /api, and the WebSocket feed at /api/stream. OpenAPI/docs disabled
to keep the control surface quiet.
"""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI

from webdash.api import control, models, monitor
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

    app.include_router(monitor.router)
    app.include_router(models.router)
    app.include_router(control.router)
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

    if host not in ("127.0.0.1", "localhost", "::1"):
        raise ValueError("refusing non-localhost bind for the control dashboard")
    token = get_or_create_token()
    print("\n  OpenElia dashboard →  "
          f"http://{host}:{port}/#token={token}\n"
          "  (token also required as 'Authorization: Bearer <token>' for /api)\n")


async def serve(host: str = "127.0.0.1", port: int = 8765) -> None:
    """Async launcher — runs inside an existing event loop (e.g. main.py's asyncio.run)."""
    import uvicorn

    _banner(host, port)
    config = uvicorn.Config(app, host=host, port=port, log_level="info")
    await uvicorn.Server(config).serve()


def run(host: str = "127.0.0.1", port: int = 8765) -> None:
    """Sync launcher for standalone use (no running event loop)."""
    import asyncio

    asyncio.run(serve(host, port))
