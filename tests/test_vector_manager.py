"""
tests/test_vector_manager.py — VectorManager ChromaDB wrapper.

ChromaDB is mocked at the module level so tests run without a real DB.
Covers: index_event calls collection.add with correct fields,
        search delegates to collection.query, check_cache returns
        cached text when distance < threshold, returns None when above,
        cache_response delegates to index_event.
"""
import pytest
from unittest.mock import MagicMock, patch, call


@pytest.fixture()
def mock_collection():
    col = MagicMock()
    col.query.return_value = {"documents": [], "distances": []}
    return col


@pytest.fixture()
def vm(mock_collection):
    """VectorManager with chromadb stubbed by injecting into lazy-init cache."""
    from vector_manager import VectorManager
    manager = VectorManager(db_path="/tmp/test_vector_db")
    # Bypass lazy property — inject mock directly so no real DB is created
    manager._collection = mock_collection
    mock_client = MagicMock()
    mock_client.get_or_create_collection.return_value = mock_collection
    manager._client = mock_client
    yield manager, mock_collection


class TestIndexEvent:
    def test_calls_collection_add(self, vm):
        manager, col = vm
        manager.index_event("agent_recon", "scan", "nmap output", metadata={"target": "10.0.0.1"})
        col.add.assert_called_once()
        kwargs = col.add.call_args
        assert kwargs[1]["documents"] == ["nmap output"]

    def test_metadata_includes_source_and_type(self, vm):
        manager, col = vm
        manager.index_event("recon", "finding", "open port 22")
        meta = col.add.call_args[1]["metadatas"][0]
        assert meta["source"] == "recon"
        assert meta["type"] == "finding"

    def test_metadata_includes_timestamp(self, vm):
        manager, col = vm
        manager.index_event("recon", "scan", "content")
        meta = col.add.call_args[1]["metadatas"][0]
        assert "timestamp" in meta

    def test_id_is_unique_per_call(self, vm):
        manager, col = vm
        manager.index_event("a", "scan", "c1")
        manager.index_event("a", "scan", "c2")
        ids1 = col.add.call_args_list[0][1]["ids"][0]
        ids2 = col.add.call_args_list[1][1]["ids"][0]
        assert ids1 != ids2

    def test_custom_metadata_merged(self, vm):
        manager, col = vm
        manager.index_event("a", "vuln", "text", metadata={"severity": "critical"})
        meta = col.add.call_args[1]["metadatas"][0]
        assert meta["severity"] == "critical"


class TestSearch:
    def test_delegates_to_collection_query(self, vm):
        manager, col = vm
        col.query.return_value = {"documents": [["result"]], "distances": [[0.1]]}
        result = manager.search("nmap scan results", limit=3)
        col.query.assert_called_once_with(query_texts=["nmap scan results"], n_results=3)
        assert result == {"documents": [["result"]], "distances": [[0.1]]}


class TestCheckCache:
    def test_returns_none_when_no_results(self, vm):
        manager, col = vm
        col.query.return_value = {"documents": [], "distances": []}
        assert manager.check_cache("What is the status?") is None

    def test_returns_cached_text_when_close_enough(self, vm):
        manager, col = vm
        col.query.return_value = {
            "documents": [["cached response"]],
            "distances": [[0.05]],  # below default threshold of 0.1
        }
        result = manager.check_cache("What is the status?")
        assert result == "cached response"

    def test_returns_none_when_distance_above_threshold(self, vm):
        manager, col = vm
        col.query.return_value = {
            "documents": [["cached response"]],
            "distances": [[0.5]],  # above threshold
        }
        assert manager.check_cache("What is the status?") is None

    def test_exception_in_query_returns_none(self, vm):
        manager, col = vm
        col.query.side_effect = RuntimeError("DB unavailable")
        assert manager.check_cache("any prompt") is None


class TestCacheResponse:
    def test_delegates_to_index_event_with_llm_cache_type(self, vm):
        manager, col = vm
        manager.cache_response("What is open?", "Port 22 is open.")
        col.add.assert_called_once()
        meta = col.add.call_args[1]["metadatas"][0]
        assert meta["type"] == "llm_cache"
        assert meta["response"] == "Port 22 is open."
