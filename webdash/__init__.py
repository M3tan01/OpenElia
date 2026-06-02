"""
webdash — FastAPI web dashboard for OpenElia.

Read-only monitoring (Phase 1) + control (Phase 2) over the existing engine
objects (StateManager, GraphManager, CostTracker, ModelManager, AuditLogger,
ScopeValidator). Binds to 127.0.0.1 only; every /api route is bearer-token gated.

Launch via:  python main.py dashboard --web
"""
