"""
tests/test_vector_manager.py — VectorManager sqlite/FTS5 backend.

Backed by stdlib sqlite3 (no chromadb). Tests run against a real temp DB.
Covers: index_event persists a searchable row, search returns chromadb-shaped
dicts and tolerates FTS-unsafe input, get_cached_response is EXACT-match
(no fuzzy collisions), cache_response round-trips, read paths never raise.
"""
import pytest

from vector_manager import VectorManager


@pytest.fixture()
def vm(tmp_path):
    return VectorManager(db_path=str(tmp_path / "vec"))


class TestIndexEvent:
    def test_indexed_event_is_searchable(self, vm):
        vm.index_event("agent_recon", "scan", "nmap found open port 22", metadata={"target": "10.0.0.1"})
        result = vm.search("nmap port", limit=5)
        assert "nmap found open port 22" in result["documents"][0]

    def test_metadata_source_and_type_preserved(self, vm):
        vm.index_event("recon", "finding", "open port 22 detected")
        meta = vm.search("open port", limit=1)["metadatas"][0][0]
        assert meta["source"] == "recon"
        assert meta["type"] == "finding"
        assert "timestamp" in meta

    def test_custom_metadata_merged(self, vm):
        vm.index_event("a", "vuln", "sql injection here", metadata={"severity": "critical"})
        meta = vm.search("injection", limit=1)["metadatas"][0][0]
        assert meta["severity"] == "critical"


class TestSearch:
    def test_returns_chromadb_shape(self, vm):
        result = vm.search("anything", limit=3)
        assert set(result) == {"documents", "metadatas", "distances"}
        assert result["documents"] == [[]]  # empty DB → empty inner list

    def test_limit_is_respected(self, vm):
        for i in range(5):
            vm.index_event("s", "scan", f"finding number {i} port open")
        result = vm.search("finding port", limit=2)
        assert len(result["documents"][0]) <= 2

    def test_fts_unsafe_query_does_not_raise(self, vm):
        vm.index_event("s", "scan", "target 10.0.0.1 CVSS:3.1/AV:N score high")
        # Raw operator chars would break a naive FTS5 MATCH; must not raise.
        result = vm.search("CVSS:3.1/AV:N -flag 10.0.0.1", limit=5)
        assert isinstance(result["documents"][0], list)

    def test_empty_query_returns_empty(self, vm):
        vm.index_event("s", "scan", "some content")
        assert vm.search("", limit=5)["documents"] == [[]]


class TestCache:
    def test_exact_prompt_round_trips(self, vm):
        vm.cache_response("What ports are open?", "Port 22 is open.")
        assert vm.get_cached_response("What ports are open?") == "Port 22 is open."

    def test_miss_returns_none(self, vm):
        assert vm.get_cached_response("never cached") is None

    def test_different_prompt_is_a_miss_no_fuzzy(self, vm):
        # Exact-match only: a *similar* prompt must NOT return another's answer.
        vm.cache_response("Scan host 10.0.0.1 for open ports", "result A")
        assert vm.get_cached_response("Scan host 10.0.0.2 for open ports") is None

    def test_cache_overwrites_same_key(self, vm):
        vm.cache_response("prompt X", "old")
        vm.cache_response("prompt X", "new")
        assert vm.get_cached_response("prompt X") == "new"
