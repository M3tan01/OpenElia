"""
tests/test_orchestrator_llm.py — Regression tests for Orchestrator LLMClient alignment.

Verifies that Orchestrator.__init__ correctly unpacks the 3-tuple returned by
LLMClient.create() and that _classify() passes is_local to cost_tracker.track_usage().
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from openai import AsyncOpenAI



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
        from orchestrator import Orchestrator
        mock_client = _make_mock_client()

        with patch("orchestrator.LLMClient.create", return_value=(mock_client, "llama3.1:8b", True)):
            orch = Orchestrator(state_manager)  # must not raise

        assert orch._orchestrator_model == "llama3.1:8b"
        assert orch._is_local is True
        assert orch.client is mock_client

    def test_init_stores_is_local_false_for_cloud(self, state_manager):
        """_is_local is False when LLMClient resolves to a cloud provider."""
        from orchestrator import Orchestrator
        mock_client = _make_mock_client()

        with patch("orchestrator.LLMClient.create", return_value=(mock_client, "gpt-4o", False)):
            orch = Orchestrator(state_manager)

        assert orch._is_local is False
        assert orch._orchestrator_model == "gpt-4o"

    @pytest.mark.asyncio
    async def test_classify_passes_is_local_to_cost_tracker(self, state_manager):
        """_classify() must pass is_local=self._is_local to cost_tracker.track_usage()."""
        from orchestrator import Orchestrator
        mock_client = _make_mock_client()

        # Fake a valid classify response
        fake_response = MagicMock()
        fake_response.choices = [MagicMock()]
        fake_response.choices[0].message.content = '{"domain": "red", "confidence": 0.9, "reason": "test"}'
        fake_response.usage.prompt_tokens = 50
        fake_response.usage.completion_tokens = 20
        mock_client.chat.completions.create = AsyncMock(return_value=fake_response)

        with patch("orchestrator.LLMClient.create", return_value=(mock_client, "llama3.1:8b", True)):
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
