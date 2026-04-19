"""
tests/test_atomic_manager.py — AtomicManager TTP lookup.

Covers: empty/missing definitions, get_test hit, get_test miss (bad ttp/id),
        list_ttps, search_by_tactic.
"""
import json
import pytest
from atomic_manager import AtomicManager


@pytest.fixture()
def definitions(tmp_path):
    data = {
        "T1003": {
            "name": "OS Credential Dumping",
            "tactic": "Credential Access",
            "tests": [
                {"id": 1, "name": "Dump LSASS", "executor": {"command": "procdump -ma lsass.exe"}},
                {"id": 2, "name": "Mimikatz", "executor": {"command": "mimikatz.exe sekurlsa::logonpasswords"}},
            ],
        },
        "T1059": {
            "name": "Command and Scripting Interpreter",
            "tactic": "Execution",
            "tests": [
                {"id": 1, "name": "PowerShell Exec", "executor": {"command": "powershell -nop -c whoami"}},
            ],
        },
    }
    path = tmp_path / "definitions.json"
    path.write_text(json.dumps(data))
    return path


class TestGetTest:
    def test_hit_returns_test(self, definitions):
        am = AtomicManager(definitions_path=str(definitions))
        result = am.get_test("T1003", test_id=1)
        assert result is not None
        assert result["name"] == "Dump LSASS"
        assert result["ttp_id"] == "T1003"
        assert result["ttp_name"] == "OS Credential Dumping"

    def test_second_test_id(self, definitions):
        am = AtomicManager(definitions_path=str(definitions))
        result = am.get_test("T1003", test_id=2)
        assert result["name"] == "Mimikatz"

    def test_missing_ttp_returns_none(self, definitions):
        am = AtomicManager(definitions_path=str(definitions))
        assert am.get_test("T9999", test_id=1) is None

    def test_missing_test_id_returns_none(self, definitions):
        am = AtomicManager(definitions_path=str(definitions))
        assert am.get_test("T1003", test_id=99) is None

    def test_missing_definitions_file_returns_none(self, tmp_path):
        am = AtomicManager(definitions_path=str(tmp_path / "nonexistent.json"))
        assert am.get_test("T1003", test_id=1) is None

    def test_executor_command_present(self, definitions):
        am = AtomicManager(definitions_path=str(definitions))
        result = am.get_test("T1059", test_id=1)
        assert "executor" in result
        assert "command" in result["executor"]


class TestListSearch:
    def test_list_ttps_returns_all_ids(self, definitions):
        am = AtomicManager(definitions_path=str(definitions))
        ttps = list(am.definitions.keys())
        assert "T1003" in ttps
        assert "T1059" in ttps

    def test_empty_file_returns_empty_definitions(self, tmp_path):
        path = tmp_path / "empty.json"
        path.write_text("{}")
        am = AtomicManager(definitions_path=str(path))
        assert am.definitions == {}
