"""
webdash — FastAPI web dashboard for OpenElia.

Read-only monitoring (Phase 1) + control (Phase 2) over the existing engine
objects (StateManager, GraphManager, CostTracker, ModelManager, AuditLogger,
ScopeValidator). Binds 0.0.0.0 (LAN-exposed); PrivateClientMiddleware 403s any
peer that is not RFC1918-private or loopback, and every /api route is bearer-token gated.

Launch via:  python main.py dashboard --web
"""
