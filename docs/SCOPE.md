# OpenElia — Scope & Anti-Bloat Guardrail

This file defines what OpenElia **is**, what it is **not**, and rules that keep it from
sprawling. Consult it before adding a subsystem, dependency, or UI. If a proposed change
does not fit here, it needs an explicit scope decision first.

## What OpenElia is (shipped core)

A single-operator, localhost, lab/research purple-team orchestration tool:

- **CLI engine** (`main.py`, `orchestrator.py`, `core/`, `agents/`): red / blue / purple /
  forge operations plus `check`, `status`, `nmap`, `msf`, `sbom`, `archive`, `lock`/`unlock`.
- **Agents** (`agents/red`, `agents/blue`, `reporter_agent.py`): LLM tool-loop agents with
  human-in-the-loop gates on sensitive actions.
- **MCP servers** (`mcp_servers/`): atomic, memory, graph, siem, pivot, red_recon,
  blue_remediate, blue_telemetry, threat_intel, vault — accessed only through `MCPGateway`.
- **Security layers** (`security_manager.py`): RoE scope gate (fail-closed), semantic
  firewall, HMAC audit chain, PII privacy guard, OS-keyring secret store.
- **Web dashboard** (`webdash/`): FastAPI + React console, **127.0.0.1 only**, token-gated.

## What OpenElia is not (out of scope)

- **Not a multi-operator team server.** No concurrent operators, no mTLS mesh, no remote
  exposure. See `docs/superpowers/plans/2026-06-03-v2-multi-operator.md` — that is a
  roadmap design, not a commitment.
- **Not a turnkey product.** Integrations require configuration and degrade gracefully
  when unconfigured.
- **Not a second UI host.** There is one CLI (Python) and one dashboard (webdash). Do not
  reintroduce a parallel CLI (a top-level `src/` TypeScript CLI was removed for this reason).

## Anti-bloat rules

1. **No vendored third-party source in-tree.** Reference upstream by pinned version /
   submodule / install-time fetch. Do not commit another project's checkout.
2. **No build artifacts or environments in git.** `venv/`, `.venv/`, `node_modules/`,
   `__pycache__/`, coverage/SAST reports, generated graph exports, and large data bundles
   (e.g. the 51 MB MITRE STIX file) stay out via `.gitignore`. They may exist locally.
3. **New heavyweight dependency ⇒ justify or make it optional.** A dependency that backs
   one thin module belongs in an optional extra, not the core `dependencies` list.
4. **One capability, one home.** Before adding a memory/audit/log/config layer, check for
   an existing one to extend (`core/jsonl.py`, `state_manager.py`, `vector_manager.py`,
   `graph_manager.py`).
5. **Docs match reality.** New features land with honest wording and a note in the
   **Maturity & requirements** README section if they are mock-only or config-gated.
6. **Keep versions in sync.** `pyproject.toml`, `COMMANDS.txt` header, and `CHANGELOG.md`
   must agree on the current version.
