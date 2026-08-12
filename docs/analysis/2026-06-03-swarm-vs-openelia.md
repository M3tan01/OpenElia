# Pentest-Swarm-AI vs. OpenElia — Architectural Comparison & Upgrade Roadmap

**Date:** 2026-06-03
**Reference repo:** `Pentest-Swarm-AI` (Armur AI) — Go 1.24, read-only study target, *not* modified.
**Subject repo:** `OpenElia` — Python 3.11 async purple-team orchestrator.
**Status note:** The four highest-value gaps identified here are **already implemented** on branch
`feat/swarm-prioritization` (6 commits, local). This document is the analysis that backs that work
and scopes what remains.

---

## 1. Architecture Comparison

| Axis | OpenElia | Pentest-Swarm-AI |
|---|---|---|
| **Language / runtime** | Python 3.11, `asyncio` | Go 1.24, goroutines |
| **Coordination model** | Stateless orchestrator (message broker) → tier-based `AsyncWorkerPool` (RECON→ANALYSIS→EXECUTION) | Stigmergic **blackboard** — agents self-trigger on finding predicates; scheduler only caps concurrency/budget |
| **Control flow** | Orchestrator pushes a *static* RED sequence; tiers stratify ordering | **Decentralized** — no planner. `scheduler.go`: "does NOT plan — each agent's trigger predicate decides what it picks up" |
| **Shared state** | SQLite `engagement.db` + NetworkX `attack_surface.json`; poll-based message bus | Blackboard (`board.go`, Postgres-backed) with per-finding **pheromone weight + decay** |
| **Resource loading** | JIT skill injection, MCP gateway, token economy | Tool registry + per-playbook tool lists |
| **Trust / integrity** | HMAC-chained audit log | **Ed25519 per-agent provenance signatures** + **MemoryGraft detector** (poisoning heuristics) |
| **Scope enforcement** | `security_manager.enforce_security_gate()` — ScopeValidator + semantic-firewall DESTRUCTIVE_PATTERNS | `scope.go` boundary validation per write |
| **Model flexibility** | Multi-provider, model-agnostic | LLM abstraction (`internal/llm`) |

### The core philosophical split

OpenElia is **orchestrator-driven and stateless**: the brain pushes tasks down tiers; agents are dumb
executors. This is deterministic, auditable, and easy to reason about — its strength for a purple-team
C2 console where every action must be attributable.

Pentest-Swarm is **stigmergy-driven**: there is no brain. Agents read the blackboard, and a trigger
predicate (`shouldRun(finding) bool`) decides whether an agent wakes. Coordination is *emergent* —
recon posts `PORT_OPEN`, the classifier wakes on it, posts `SERVICE_ID`, the exploit agent wakes on
*that*. Pheromone decay means stale findings lose pull over time, so the swarm naturally drifts toward
fresh, high-value leads.

**Neither is strictly superior.** Stigmergy scales coordination without a central bottleneck but is
harder to audit and bound. OpenElia's model is bounded and auditable but leaves coordination signal
(risk scores, graph value) on the floor. The upgrade path is to **borrow the swarm's signals without
abandoning the orchestrator** — which is exactly what the branch does.

---

## 2. Gap Analysis

### Gaps OpenElia had (now closed on `feat/swarm-prioritization`)

| # | Swarm capability | OpenElia before | Port shipped |
|---|---|---|---|
| 1 | Pheromone-weighted, decaying prioritization | FIFO per tier; `risk_calculator` output was display-only | `core/prioritizer.py` + `PriorityQueue` in `worker_pool.py`; `score = base·detection_weight·decay (+graph)` |
| 2 | Cleanup / rollback registry | Absent — hooks only cleared LLM context | `core/cleanup_registry.py`: LIFO, gated, crash-safe; fires on kill-switch `lock` |
| 3 | Attack graph as a decision oracle | `graph_manager` write-only; never read by scheduler | `graph_manager.target_signal()` feeds `prioritizer.score` |
| 4 | CVSS v3.1 in findings | CVSS only in vuln phase | `cvss_score`/`cvss_vector` columns + `add_finding`/`log_finding` plumbing |

### Gaps still open (Swarm has, OpenElia does not)

| Capability | Where in Swarm | OpenElia status | Fit |
|---|---|---|---|
| **Per-write provenance signatures** | `provenance/` — Ed25519 sign+verify each finding | HMAC chains the *audit log*, but individual findings in `engagement.db` are unsigned; any code path can write any `agent_name` | **High** — strong fit for a multi-operator v2 (deconfliction + tamper-evidence) |
| **Memory-poisoning detector** | `memorygraft/detector.go` — burst / repeat-title / duplicate / type-mismatch heuristics | None. OpenElia trusts agent writes implicitly | **Medium** — relevant once findings drive scheduling (a poisoned finding now changes priority) |
| **Per-agent budget caps** | scheduler `agentLimits` (rate) + budget poll | Global `cost_tracker` only | **Medium** |
| **Engagement playbooks** | `playbooks/*.yaml` (bug-bounty, owasp-top10, internal-network, ctf-solver, external-asm, api-security, ci-cd) | Only APT personas via Adversary Forge | **High for UX** — see §3 |
| **Pub/sub agent triggering** | blackboard predicates; agents self-wake | Poll-based bus; orchestrator pushes static sequence | **v2 arc** — the real stigmergy endgame |

### Where OpenElia is already superior

- **Semantic firewall + DESTRUCTIVE_PATTERNS** scope gate is richer than Swarm's boundary check, and is
  enforced *inside* the new cleanup-registry undo path (Swarm's cleanup runs are less guarded).
- **JIT skill injection + token economy** — Swarm has no equivalent token-budget discipline at the
  resource-loading layer.
- **HMAC-chained audit** gives tamper-evidence across the *whole* engagement timeline, not just
  per-finding.
- **Kill-switch (`lock`/`unlock`)** with cleanup-on-lock is now a clean, auditable safety story.
- **Purple-team duality** (RED + BLUE + remediation agents) — Swarm is offense-only.

---

## 3. CLI & UX Evaluation

### Subcommand surface, side by side

| OpenElia (`main.py`) | Swarm (`cli/*.go`) |
|---|---|
| `red` `blue` `purple` `hybrid` | `campaign` (single entry, swarm decides) |
| `nmap` `msf` `forge` `sbom` | `scan` `submit` `program` |
| `doctor` `check` `status` | `doctor` `config` `scope` |
| `lock` `unlock` `archive` `clear` | — |
| `report` `dashboard` | `report` `serve` `ui` |
| `model` `set` `auth` | `init` `mcp` `explain` `assist` |
| `execute-remediation` | `playbook` `ctf` `fp` `demo` |

### Swarm CLI/UX patterns worth adopting

**(a) `playbook` — declarative engagement templates.** The single biggest UX win. Swarm ships
`playbooks/*.yaml` describing phases, tools, and `post_analysis` prompts. An operator runs one named
playbook instead of hand-sequencing `red`/`nmap`/`msf`. OpenElia already has the *engine* (tiered pool +
agents); it lacks the *declarative front door*.

```python
# proposed: core/playbook.py — load + validate a YAML engagement template
import yaml
from pydantic import BaseModel

class PlaybookPhase(BaseModel):
    name: str
    tools: list[str] = []
    post_analysis: str | None = None        # LLM directive after the phase

class Playbook(BaseModel):
    name: str
    description: str = ""
    variables: dict[str, str] = {}          # e.g. {"target": "..."}
    phases: list[PlaybookPhase]

    @classmethod
    def load(cls, path: str) -> "Playbook":
        with open(path) as f:
            return cls(**yaml.safe_load(f))
```

```python
# main.py — new subcommand wiring (mirrors existing add_parser pattern)
p_pb = sub.add_parser("playbook", help="run a declarative engagement template")
p_pb.add_argument("name")                   # e.g. owasp-top10
p_pb.add_argument("--target", required=True)
p_pb.add_argument("--var", action="append", default=[])  # k=v overrides
# cmd_playbook(): Playbook.load -> for phase: enqueue tier tasks w/ prioritizer score
```

**(b) `explain` — dry-run / rationale mode.** Swarm's `explain` shows *why* the swarm would act before
acting. OpenElia should expose the now-computed priority + graph signal:

```python
# main.py: `status --explain` or new `explain` subcommand
#   For each queued EXECUTION task print:
#   target | success_prob | detection_risk | graph_signal | final_priority
#   -> operator sees the scheduling decision instead of a black box.
```
This is nearly free now: `prioritizer.score()` already returns the number; surface it instead of
discarding it.

**(c) `scope` as a first-class command.** OpenElia enforces scope via `roe.json` + the security gate,
but there's no operator-facing `scope show / scope add / scope check <target>`. Swarm's `scope.go`
makes the authorized boundary inspectable:

```python
# main.py: `scope show` (print roe.json CIDRs), `scope check <ip>` (gate dry-run)
#   cmd_scope_check: ScopeValidator(...).is_in_scope(ip) -> green/red, no execution
```

**(d) `fp` — false-positive management.** Swarm tracks an FP cache so re-runs don't re-report known
noise. OpenElia's findings table could gain a `false_positive` flag + a `fp mark <finding_id>` command.

### UX features NOT worth porting

- Swarm's `serve`/`ui` (Next.js) — OpenElia already has the webdash C2 console; don't fork effort.
- SARIF export — low fit for a C2 console (it's a code-scanning interchange format).

---

## 4. Actionable Roadmap

### Already done (branch `feat/swarm-prioritization`)
Priority+decay scheduling, cleanup registry, graph-as-oracle, CVSS in findings. Reuses OpenElia's
*already-computed* `risk_calculator` signal — low churn, no new control path.

```python
# core/prioritizer.py (shipped) — the central pattern: turn a discarded signal into scheduling order
def score(success_probability, detection_risk, created_at=None, now=None,
          graph_signal=0.0, half_life_s=None):
    base   = max(0, min(100, success_probability)) / 100.0
    weight = _DETECTION_WEIGHT.get((detection_risk or "medium").lower(), 0.7)
    decay  = decay_factor(created_at, now=now, half_life_s=half_life_s)  # 0.5 ** (age/hl)
    return base * weight * decay + max(0.0, graph_signal)
```

### Next, in priority order

**R1 — `playbook` subcommand (§3a).** Highest UX leverage, no architectural risk. Declarative YAML →
existing tier pool. Ship 3 templates first: `recon-only`, `web-owasp`, `internal-network`.

**R2 — `explain` / `scope` operator visibility (§3b, §3c).** Surface the priority math and the scope
boundary. Both are read-only, cheap, and make the new scheduler legible to the operator.

**R3 — Per-finding provenance (sign-on-write).** Adopt Swarm's `provenance` pattern in Python. This is
the bridge to v2 multi-operator: signed findings let operators trust each other's writes and deconflict.

```python
# proposed: core/provenance.py
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

class FindingSigner:
    """One keypair per operator. Sign every finding write; verify on read."""
    def __init__(self, key: Ed25519PrivateKey):
        self._key = key
    def sign(self, engagement_id, agent, ftype, target, data: bytes, ts: int) -> bytes:
        msg = f"{engagement_id}|{agent}|{ftype}|{target}|{ts}".encode() + data
        return self._key.sign(msg)
    # store sig + pubkey-id alongside the finding row; verify in state_manager reads
```
Pairs with a lightweight `memorygraft`-style anomaly check (burst / duplicate-title) once findings drive
scheduling, since a poisoned finding now moves priority.

**R4 — Per-agent budget caps.** Extend `cost_tracker` from a global ceiling to per-agent limits
(mirror scheduler `agentLimits`). Prevents one runaway agent from draining the engagement budget.

### v2 / futuristic arc (design now, build later)
True stigmergy: findings carry decaying pheromone weights (the decay primitive already exists in
`prioritizer`); agents self-trigger on finding-type threshold predicates via **pub/sub**, replacing the
orchestrator's static RED sequence. The bridge is evolving `state_manager`'s poll-based bus into pub/sub.
Tasks C+D (priority + graph signal) shipped on this branch are the incremental stepping stones — they add
the *signals* stigmergy needs without yet removing the orchestrator. Ties directly into the v2
multi-operator doc: priority + graph + signed provenance become shared deconfliction signals across
operators.

---

## Verification of claims
- Swarm internals read: `internal/swarm/{scheduler,blackboard,memorygraft,provenance,agents}`,
  `internal/pipeline/cleanup*`, `playbooks/*.yaml`, `cli/*.go`.
- OpenElia surface read: `main.py` subcommands, `graph_manager.py`, `core/{prioritizer,worker_pool}.py`,
  tests under `tests/`.
- Branch state: 6 commits ahead of `origin/main`, local only.
