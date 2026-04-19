"""
tests/test_graph_manager.py — GraphManager attack surface graph operations.

Covers: add_host, add_service, add_vulnerability, add_credential,
        find_paths, get_neighbors, query_by_type, get_summary,
        export_to_mermaid, get_mitre_heatmap.
"""
import json
import pytest
from graph_manager import GraphManager


@pytest.fixture()
def gm(tmp_path):
    return GraphManager(db_path=str(tmp_path / "state" / "graph.json"))


class TestAddAndQuery:
    def test_add_host_appears_in_summary(self, gm):
        gm.add_host("10.0.0.1", hostname="target", os="Linux")
        assert gm.get_summary()["hosts"] == 1

    def test_add_service_linked_to_host(self, gm):
        gm.add_host("10.0.0.1")
        gm.add_service("10.0.0.1", 22, "tcp", "ssh", version="7.4")
        neighbors = gm.get_neighbors("10.0.0.1")
        assert any("22" in n for n in neighbors)

    def test_add_vulnerability_linked_to_service(self, gm):
        gm.add_host("10.0.0.1")
        gm.add_service("10.0.0.1", 443, "tcp", "https")
        service_id = "10.0.0.1:443/tcp"
        gm.add_vulnerability(service_id, "CVE-2021-44228", "critical", "Log4Shell")
        vuln_nodes = gm.query_by_type("vulnerability")
        assert "CVE-2021-44228" in vuln_nodes

    def test_add_credential_linked_to_target(self, gm):
        gm.add_host("10.0.0.1")
        gm.add_credential("10.0.0.1", alias="admin-cred", username="admin")
        cred_nodes = gm.query_by_type("credential")
        assert any("admin-cred" in n for n in cred_nodes)

    def test_get_neighbors_unknown_node_returns_empty(self, gm):
        assert gm.get_neighbors("9.9.9.9") == []

    def test_query_by_type_filters_correctly(self, gm):
        gm.add_host("10.0.0.1")
        gm.add_host("10.0.0.2")
        gm.add_service("10.0.0.1", 80, "tcp", "http")
        hosts = gm.query_by_type("host")
        services = gm.query_by_type("service")
        assert len(hosts) == 2
        assert len(services) == 1


class TestFindPaths:
    def test_direct_path_found(self, gm):
        gm.add_host("10.0.0.1")
        gm.add_service("10.0.0.1", 22, "tcp", "ssh")
        paths = gm.find_paths("10.0.0.1", "10.0.0.1:22/tcp")
        assert len(paths) > 0

    def test_no_path_returns_empty(self, gm):
        gm.add_host("10.0.0.1")
        gm.add_host("10.0.0.2")
        paths = gm.find_paths("10.0.0.1", "10.0.0.2")
        assert paths == []


class TestGetSummary:
    def test_empty_graph_summary(self, gm):
        s = gm.get_summary()
        assert s == {"node_count": 0, "edge_count": 0, "hosts": 0, "services": 0, "vulnerabilities": 0}

    def test_summary_reflects_additions(self, gm):
        gm.add_host("10.0.0.1")
        gm.add_service("10.0.0.1", 80, "tcp", "http")
        gm.add_vulnerability("10.0.0.1:80/tcp", "CVE-2020-1234", "high")
        s = gm.get_summary()
        assert s["hosts"] == 1
        assert s["services"] == 1
        assert s["vulnerabilities"] == 1


class TestExportMermaid:
    def test_mermaid_starts_with_graph_td(self, gm):
        gm.add_host("10.0.0.1", hostname="target")
        output = gm.export_to_mermaid()
        assert output.startswith("graph TD")

    def test_mermaid_contains_host_node(self, gm):
        gm.add_host("10.0.0.1", hostname="target")
        output = gm.export_to_mermaid()
        assert "10_0_0_1" in output

    def test_mermaid_empty_graph_is_valid(self, gm):
        output = gm.export_to_mermaid()
        assert "graph TD" in output


class TestMitreHeatmap:
    def test_missing_mitre_file_returns_error(self, gm, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        result = gm.get_mitre_heatmap([{"mitre_ttp": "T1003"}])
        assert "error" in result

    def test_heatmap_counts_coverage(self, gm, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        mitre = {"Credential Access": ["T1003", "T1078"], "Execution": ["T1059"]}
        (tmp_path / "mitre_attack.json").write_text(json.dumps(mitre))
        findings = [{"mitre_ttp": "T1003"}]
        result = gm.get_mitre_heatmap(findings)
        assert "Credential Access" in result
        assert result["Credential Access"]["coverage_pct"] == 50.0
        assert "T1003" in result["Credential Access"]["tested_ttps"]
        assert "T1078" in result["Credential Access"]["missing_ttps"]


class TestPersistence:
    def test_graph_persists_across_instances(self, tmp_path):
        db = str(tmp_path / "state" / "graph.json")
        gm1 = GraphManager(db_path=db)
        gm1.add_host("10.0.0.5", hostname="persisted")
        gm2 = GraphManager(db_path=db)
        assert gm2.get_summary()["hosts"] == 1
