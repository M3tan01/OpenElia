# Design: Orchestrator LLMClient Alignment

**Date:** 2026-04-26
**Status:** Approved
**Scope:** `orchestrator.py` — 2 bug fixes + 1 new test file

---

## Background

The Apr 19 session refactored the LLM routing layer:
- `model_manager.py` — added multi-provider + per-agent hybrid override support
- `llm_client.py` — `LLMClient.create()` return type changed from `(client, model)` to `(client, model, is_local)`
- `cost_tracker.py` — added `is_local: bool` param to `track_usage()` to zero-cost local models
- `vector_manager.py` — added `check_cache()` / `cache_response()` for semantic response caching
- `base_agent.py` — fully updated to match the new API

`orchestrator.py` was **not updated** and contains 2 bugs as a result.

---

## Bugs

### Bug 1 — 2-tuple unpack crash (`orchestrator.py:64`)

`LLMClient.create()` now returns 3 values. The orchestrator unpacks 2, causing `ValueError: too many values to unpack` at instantiation — the system cannot start.

### Bug 2 — Missing `is_local` in cost tracking (`orchestrator.py:337`)

`track_usage()` is called without `is_local`, so it defaults to `False`. Every local Ollama classify call is billed at the `PRICING["default"]` rate ($10/1M input) instead of $0. Budget enforcement may fire prematurely in sessions with many classifications.

---

## Design

### Changes to `orchestrator.py`

**`__init__` — fix unpack, store `_is_local`, pass `agent_name`:**

```python
# Before
self.client, self._orchestrator_model = LLMClient.create(brain_tier="local")

# After
self.client, self._orchestrator_model, self._is_local = LLMClient.create(
    brain_tier="local",
    agent_name="orchestrator",
)
```

- `self._is_local` stored on the instance, matching the `base_agent` pattern (`self.IS_LOCAL`)
- `agent_name="orchestrator"` enables future hybrid-mode override of the classifier model via `model hybrid --agent orchestrator ...` without code changes

**`_classify()` — pass `is_local` to `track_usage`:**

```python
# Before
self.cost_tracker.track_usage(
    model=self._orchestrator_model,
    input_tokens=response.usage.prompt_tokens,
    output_tokens=response.usage.completion_tokens,
)

# After
self.cost_tracker.track_usage(
    model=self._orchestrator_model,
    input_tokens=response.usage.prompt_tokens,
    output_tokens=response.usage.completion_tokens,
    is_local=self._is_local,
)
```

### New file: `tests/test_orchestrator_llm.py`

Regression test — no live Ollama required, fully mocked:

- Patches `LLMClient.create` to return `(mock_client, "llama3.1:8b", True)`
- Instantiates `Orchestrator` — asserts no `ValueError` on unpack
- Asserts `orchestrator._is_local is True`
- Asserts `orchestrator._orchestrator_model == "llama3.1:8b"`

---

## Files Changed

| File | Change |
|---|---|
| `orchestrator.py` | Fix 2-tuple unpack → 3-tuple; add `is_local` to `track_usage` call |
| `tests/test_orchestrator_llm.py` | New — regression test for 3-tuple unpack |

## Files NOT Changed

All other files from the Apr 19 session (`model_manager.py`, `llm_client.py`, `cost_tracker.py`, `vector_manager.py`, `base_agent.py`) are correct and complete.

---

## Verification

After implementation:
1. `python -m pytest tests/test_orchestrator_llm.py -v` — must pass
2. `python -m pytest tests/test_cost_tracker.py -v` — must still pass (no regression)
3. Manual: `python main.py status` — must not crash on `Orchestrator.__init__`
