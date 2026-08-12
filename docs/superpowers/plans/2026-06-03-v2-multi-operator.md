# Plan: webdash v2 — Multi-Operator Team Server

**Status:** Roadmap / design (not yet scheduled for implementation)
**Supersedes scope of:** v1 "Out of scope" (multi-user, remote access)
**Complexity:** Large (transport, identity, concurrency, audit all change)

## Goal

Turn the single-operator localhost C2 console into a **shared team server** that
multiple authenticated operators can drive concurrently and safely against the same
engagement — without losing any v1 security invariant (RoE gate, kill-switch,
HMAC audit, secrets write-only).

Reference model: Cobalt Strike / Mythic / Sliver team servers — **per-operator
identity, deconfliction, and full attribution**, not OAuth federation.

## Decision: identity mechanism

**Primary: mutual TLS (mTLS) with per-operator client certificates.**

| Option | Verdict |
|---|---|
| **mTLS client certs** (chosen) | No external IdP, works air-gapped/proxied, identity = cert CN, server verifies at the TLS layer. Matches offensive-tooling norms. |
| Per-operator bearer tokens | Simpler than mTLS but weaker (bearer is stealable; no transport binding). Acceptable fallback if cert distribution is too heavy. |
| OAuth / OIDC | Rejected as the primary gate — needs reachable IdP, leaks engagement existence, wrong for air-gapped ops. **Optional add-on only** (below). |

**OIDC as an optional identity *bridge* (not the gate):** in a corporate SOC where
operators already have Entra/Okta identities and the team server is *inside* the
network, an OIDC login MAY map an operator to their corporate identity for audit
attribution — layered behind mTLS/VPN, never as the sole authn. Keep it a pluggable
`IdentityProvider`, off by default.

## Current surfaces that change (grounded in v1 code)

| File | v1 behavior | v2 change |
|---|---|---|
| `webdash/security.py` | one keychain bearer token | operator registry + cert/identity verification; token path kept for solo/local mode |
| `webdash/server.py` `_banner` | **refuses any non-localhost bind** | allow bind beyond localhost *only* when TLS+mTLS configured; still refuse plaintext non-localhost |
| `webdash/guards.py` | `scope_gate` audits `source="webdash"` | attribute every event to the acting operator (`source=f"operator:{cn}"`) + role check |
| `webdash/runner.py` `RunManager` | **single `_active` run** | multiple concurrent runs keyed by operator + run ownership |
| `security_manager.AuditLogger.log_event(source,...)` | source is a string | pass operator identity through as source; HMAC chain already covers integrity |
| `webdash/stream.py` | one anonymous WS feed | per-operator WS sessions + presence + cross-operator action broadcast (deconfliction) |
| frontend | token from URL fragment | cert-based (browser client cert) or operator login screen; presence panel |

## Phases

### Phase 1 — Transport hardening (prerequisite for anything remote)
- TLS termination in `serve()`: uvicorn `ssl_keyfile`/`ssl_certfile`, or document a
  localhost-only reverse proxy that does mTLS.
- Loosen `_banner` to permit a non-localhost bind **iff** TLS + client-cert
  verification are both configured; otherwise keep the hard refuse.
- mTLS: server CA, `ssl_cert_reqs=CERT_REQUIRED`, operator client certs signed by
  the team CA. Extract operator CN from the peer cert.
- Verify: a request without a valid client cert is rejected at the TLS layer; a
  plaintext non-localhost launch still raises.

### Phase 2 — Operator identity + RBAC
- `Operator` model: `{id, cn, role}` where role ∈ `lead | operator | observer`.
- Operator registry (file/SQLite), enrollment = issue+register a client cert.
- New dependency `current_operator()` resolving the peer cert CN → `Operator`.
- Role gate: `observer` = read-only (monitor + stream only); `operator` = run/lock;
  `lead` = also unlock, manage operators, abort others' runs.
- Wire role check into `guards.py` alongside the existing confirm/scope/unlocked layers.
- Verify: observer gets 403 on `/api/run/*`; operator can run but not unlock; lead can.

### Phase 3 — Concurrent runs + ownership
- `RunManager`: drop the single `_active` constraint; track `{run_id: {operator, ...}}`.
- Concurrency bounds: max concurrent runs (config), per-operator run cap.
- Run ownership: only the owning operator or a `lead` may query/abort a run.
- Engagement state is shared (`StateManager`/SQLite) — confirm concurrent-write safety
  (WAL, serialized writers) since v1 assumed a single writer.
- **Kill-switch stays global** — any operator can lock; only `lead` unlocks. Lock
  must halt *all* in-flight runs, not just the caller's.
- Verify: two operators run different targets simultaneously; a `lock` stops both;
  operator A cannot abort operator B's run.

### Phase 4 — Deconfliction + presence (the team-server value-add)
- WS presence: who is connected (operator CN + role).
- Broadcast control actions to all operators ("B launched red vs 10.0.0.5").
- Active-target map: surface targets with a live run so operators don't collide.
- Optional target soft-lock: warn/deny a second run against a target already in play.
- Verify: operator B sees operator A's launch in real time; collision warning fires.

### Phase 5 — Audit attribution + per-operator views
- Every audited event carries the acting operator (`source=operator:{cn}`).
- Audit timeline filterable by operator; `chain/verify` unchanged (HMAC already).
- Per-operator activity/cost rollups.
- Verify: audit log unambiguously attributes each control action to one operator.

## Security invariants (must survive v2 — same as v1)
- RoE scope gate, quiet hours, kill-switch all still enforced on every control action.
- Secrets remain write-only; `/api/models` never returns keys.
- No plaintext transport off localhost. mTLS or bust for remote.
- Fail-closed everywhere (unknown operator → deny; missing cert → deny).
- HMAC-chained, append-only audit — now per-operator.

## Out of scope (even for v2)
- Public-internet exposure without a VPN/bastion in front.
- Multi-tenant (separate orgs on one server) — single team, single engagement set.
- OAuth as a primary gate (only the optional OIDC attribution bridge above).

## Open questions (resolve before scheduling)
1. mTLS cert distribution — manual, or a small enrollment CLI (`openelia operator add`)?
2. Concurrent-write story for `StateManager` — is SQLite WAL enough, or move to a
   single writer task/queue?
3. Per-operator brain-model keys, or shared `ModelManager` config?
4. Run isolation — do concurrent runs share the one engagement, or get sub-engagements?
