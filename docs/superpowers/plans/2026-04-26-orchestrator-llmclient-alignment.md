# Orchestrator LLMClient Alignment Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix two bugs in `orchestrator.py` introduced when `LLMClient.create()` was updated to return a 3-tuple, then add a regression test to prevent recurrence.

**Architecture:** Two surgical line edits in `orchestrator.py` — fix the 2-tuple unpack to capture `is_local`, and pass `is_local` to `cost_tracker.track_usage()`. A new test file mocks `LLMClient.create` and asserts the orchestrator instantiates correctly and stores the right values.

**Tech Stack:** Python 3, pytest, `unittest.mock` (patch, MagicMock, AsyncMock)

---

## File Map

| Action | File | What changes |
|---|---|---|
| Modify | `orchestrator.py` | Line 64: 2-tuple → 3-tuple unpack + `agent_name`; Line 337: add `is_local=self._is_local` |
| Create | `tests/test_orchestrator_llm.py` | Regression test for 3-tuple unpack and `is_local` propagation |

---

### Task 1: Write the failing regression test

**Files:**
- Create: `tests/test_orchestrator_llm.py`

- [ ] **Step 1: Create the test file**

```python
"""
tests/test_orchestrator_llm.py — Regression tests for Orchestrator LLMClient alignment.

Verifies that Orchestrator.__init__ correctly unpacks the 3-tuple returned by
LLMClient.create() and that _classify() passes is_local to cost_tracker.track_usage().
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch, call
from openai import AsyncOpenAI


pytestmark = pytest.mark.asyncio


def _make_mock_client():
    """Return a minimal AsyncOpenAI-compatible mock."""
    return MagicMock(spec=AsyncOpenAI)


@pytest.fixture
def state_manager(tmp_path):
    from state_manager import StateManager
    sm = StateManager(db_path=str(tmp_path / "test.db"))
    sm.initialize_engagement("10.0.0.1", "single-host")
    return sm


class TestOrchestratorLLMClientAlignment:

    def test_init_unpacks_three_tuple_without_error(self, state_manager):
        """Orchestrator.__init__ must not raise ValueError when LLMClient.create returns 3 values."""
        mock_client = _make_mock_client()

        with patch("orchestrator.LLMClient.create", return_value=(mock_client, "llama3.1:8b", True)):
            from orchestrator import Orchestrator
            orch = Orchestrator(state_manager)  # must not raise

        assert orch._orchestrator_model == "llama3.1:8b"
        assert orch._is_local is True
        assert orch.client is mock_client

    def test_init_stores_is_local_false_for_cloud(self, state_manager):
        """_is_local is False when LLMClient resolves to a cloud provider."""
        mock_client = _make_mock_client()

        with patch("orchestrator.LLMClient.create", return_value=(mock_client, "gpt-4o", False)):
            from orchestrator import Orchestrator
            orch = Orchestrator(state_manager)

        assert orch._is_local is False
        assert orch._orchestrator_model == "gpt-4o"

    async def test_classify_passes_is_local_to_cost_tracker(self, state_manager):
        """_classify() must pass is_local=self._is_local to cost_tracker.track_usage()."""
        mock_client = _make_mock_client()

        # Fake a valid classify response
        fake_response = MagicMock()
        fake_response.choices = [MagicMock()]
        fake_response.choices[0].message.content = '{"domain": "red", "confidence": 0.9, "reason": "test"}'
        fake_response.usage.prompt_tokens = 50
        fake_response.usage.completion_tokens = 20
        mock_client.chat.completions.create = AsyncMock(return_value=fake_response)

        with patch("orchestrator.LLMClient.create", return_value=(mock_client, "llama3.1:8b", True)):
            from orchestrator import Orchestrator
            orch = Orchestrator(state_manager)

        with patch.object(orch.cost_tracker, "track_usage") as mock_track:
            result = await orch._classify("scan target", "10.0.0.1")

        assert result["domain"] == "red"
        mock_track.assert_called_once_with(
            model="llama3.1:8b",
            input_tokens=50,
            output_tokens=20,
            is_local=True,
        )
```

- [ ] **Step 2: Run the tests to confirm they fail**

```bash
cd "$(git rev-parse --show-toplevel)"
python -m pytest tests/test_orchestrator_llm.py -v
```

Expected output (3 failures):
```
FAILED tests/test_orchestrator_llm.py::TestOrchestratorLLMClientAlignment::test_init_unpacks_three_tuple_without_error
FAILED tests/test_orchestrator_llm.py::TestOrchestratorLLMClientAlignment::test_init_stores_is_local_false_for_cloud
FAILED tests/test_orchestrator_llm.py::TestOrchestratorLLMClientAlignment::test_classify_passes_is_local_to_cost_tracker
```

The first two will fail with `ValueError: too many values to unpack`. The third will fail because `_is_local` doesn't exist yet.

---

### Task 2: Fix the 3-tuple unpack in `orchestrator.py`

**Files:**
- Modify: `orchestrator.py:64`

- [ ] **Step 1: Open `orchestrator.py` and replace line 64**

Find this block in `Orchestrator.__init__`:

```python
        # Always use the local model for cheap task classification
        self.client, self._orchestrator_model = LLMClient.create(brain_tier="local")
```

Replace with:

```python
        # Always use the local model for cheap task classification
        self.client, self._orchestrator_model, self._is_local = LLMClient.create(
            brain_tier="local",
            agent_name="orchestrator",
        )
```

- [ ] **Step 2: Run the first two tests to verify they now pass**

```bash
cd "$(git rev-parse --show-toplevel)"
python -m pytest tests/test_orchestrator_llm.py::TestOrchestratorLLMClientAlignment::test_init_unpacks_three_tuple_without_error tests/test_orchestrator_llm.py::TestOrchestratorLLMClientAlignment::test_init_stores_is_local_false_for_cloud -v
```

Expected:
```
PASSED tests/test_orchestrator_llm.py::TestOrchestratorLLMClientAlignment::test_init_unpacks_three_tuple_without_error
PASSED tests/test_orchestrator_llm.py::TestOrchestratorLLMClientAlignment::test_init_stores_is_local_false_for_cloud
```

---

### Task 3: Fix `is_local` propagation in `_classify()`

**Files:**
- Modify: `orchestrator.py:337`

- [ ] **Step 1: Find and update the `track_usage` call inside `_classify()`**

Find this block in `Orchestrator._classify()`:

```python
        if response.usage:
            self.cost_tracker.track_usage(
                model=self._orchestrator_model,
                input_tokens=response.usage.prompt_tokens,
                output_tokens=response.usage.completion_tokens,
            )
```

Replace with:

```python
        if response.usage:
            self.cost_tracker.track_usage(
                model=self._orchestrator_model,
                input_tokens=response.usage.prompt_tokens,
                output_tokens=response.usage.completion_tokens,
                is_local=self._is_local,
            )
```

- [ ] **Step 2: Run all three tests to verify they all pass**

```bash
cd "$(git rev-parse --show-toplevel)"
python -m pytest tests/test_orchestrator_llm.py -v
```

Expected:
```
PASSED tests/test_orchestrator_llm.py::TestOrchestratorLLMClientAlignment::test_init_unpacks_three_tuple_without_error
PASSED tests/test_orchestrator_llm.py::TestOrchestratorLLMClientAlignment::test_init_stores_is_local_false_for_cloud
PASSED tests/test_orchestrator_llm.py::TestOrchestratorLLMClientAlignment::test_classify_passes_is_local_to_cost_tracker
```

---

### Task 4: Verify no regressions in existing test suite

**Files:** None

- [ ] **Step 1: Run the existing orchestrator pool tests**

```bash
cd "$(git rev-parse --show-toplevel)"
python -m pytest tests/test_orchestrator_pool.py -v
```

Expected: all tests pass (same count as before this change).

- [ ] **Step 2: Run the cost tracker tests**

```bash
python -m pytest tests/test_cost_tracker.py -v
```

Expected: all tests pass.

- [ ] **Step 3: Run the model manager tests**

```bash
python -m pytest tests/test_model_manager.py -v
```

Expected: all tests pass.

---

### Task 5: Commit

**Files:** All modified and created files

- [ ] **Step 1: Stage and commit**

```bash
cd "$(git rev-parse --show-toplevel)"
git add orchestrator.py tests/test_orchestrator_llm.py
git commit -m "fix: align orchestrator with LLMClient 3-tuple return

LLMClient.create() was updated in the Apr 19 session to return
(client, model, is_local). orchestrator.py was not updated:

- Fix ValueError: too many values to unpack in __init__
- Store _is_local on self; pass agent_name='orchestrator' for
  future hybrid-mode classifier override support
- Pass is_local=self._is_local to cost_tracker.track_usage() so
  local Ollama classify calls are billed at $0 not default rate

Adds tests/test_orchestrator_llm.py as regression coverage."
```

---

## Self-Review

**Spec coverage:**
- Bug 1 (2-tuple unpack) → Task 2 ✓
- Bug 2 (missing is_local in track_usage) → Task 3 ✓
- Regression test → Task 1 ✓
- Verification → Task 4 ✓

**Placeholder scan:** None found. All code blocks are complete and runnable.

**Type consistency:** `_is_local` (bool) defined in Task 2, consumed in Task 3 — consistent. `_orchestrator_model` (str) unchanged — consistent.
