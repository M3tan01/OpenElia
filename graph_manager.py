#!/usr/bin/env python3
import networkx as nx
import json
import os

class GraphManager:
    def __init__(self, db_path="state/attack_surface.json"):
        self.db_path = db_path
        self.graph = nx.DiGraph()
        self._load()

    def _load(self):
        if os.path.exists(self.db_path):
            try:
                with open(self.db_path, "r") as f:
                    data = json.load(f)
                    self.graph = nx.node_link_graph(data)
            except Exception as e:
                print(f"Error loading graph: {e}")
                self.graph = nx.DiGraph()

    def _save(self):
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        data = nx.node_link_data(self.graph)
        with open(self.db_path, "w") as f:
            json.dump(data, f, indent=2)

    def add_host(self, ip, hostname=None, os=None):
        self.graph.add_node(ip, type="host", hostname=hostname, os=os)
        self._save()

    def add_service(self, host_ip, port, protocol, service_name, version=None):
        service_id = f"{host_ip}:{port}/{protocol}"
        self.graph.add_node(service_id, type="service", port=port, protocol=protocol, name=service_name, version=version)
        self.graph.add_edge(host_ip, service_id, relation="HAS_SERVICE")
        self._save()

    def add_vulnerability(self, service_id, cve_id, severity, description=None):
        self.graph.add_node(cve_id, type="vulnerability", severity=severity, description=description)
        self.graph.add_edge(service_id, cve_id, relation="VULNERABLE_TO")
        self._save()

    def add_credential(self, target_id, alias, username=None):
        cred_id = f"cred:{alias}"
        self.graph.add_node(cred_id, type="credential", alias=alias, username=username)
        self.graph.add_edge(cred_id, target_id, relation="ACCESS_TO")
        self._save()

    def find_paths(self, source, target):
        try:
            paths = list(nx.all_simple_paths(self.graph, source, target))
            return paths
        except nx.NetworkXNoPath:
            return []
        except Exception as e:
            return str(e)

    def get_neighbors(self, node_id):
        if node_id in self.graph:
            return list(self.graph.neighbors(node_id))
        return []

    def query_by_type(self, node_type):
        return [n for n, d in self.graph.nodes(data=True) if d.get("type") == node_type]

    def export_to_mermaid(self):
        """Export the graph structure to Mermaid.js flowchart format."""
        lines = ["graph TD"]
        
        # Add nodes with labels
        for node, data in self.graph.nodes(data=True):
            node_type = data.get("type", "unknown")
            label = f"{node}"
            if node_type == "host" and data.get("hostname"):
                label = f"{node} ({data.get('hostname')})"
            
            # Use different shapes for node types
            if node_type == "host":
                lines.append(f'    {node.replace(".", "_")}["{label}"]')
            elif node_type == "service":
                lines.append(f'    {node.replace(".", "_").replace(":", "_").replace("/", "_")}(("{label}"))')
            elif node_type == "vulnerability":
                lines.append(f'    {node.replace("-", "_")}["{label}"]:::vuln')
            else:
                lines.append(f'    {node}["{label}"]')

        # Add edges
        for u, v, data in self.graph.edges(data=True):
            relation = data.get("relation", "")
            u_id = u.replace(".", "_").replace(":", "_").replace("/", "_")
            v_id = v.replace(".", "_").replace(":", "_").replace("/", "_").replace("-", "_")
            lines.append(f'    {u_id} -- "{relation}" --> {v_id}')

        lines.append("    classDef vuln fill:#f96,stroke:#333,stroke-width:2px;")
        return "\n".join(lines)

    def get_mitre_heatmap(self, findings):
        """
        Cross-reference findings with MITRE ATT&CK tactics.
        'findings' is a list of finding dicts from state.
        """
        mitre_path = "mitre_attack.json"
        if not os.path.exists(mitre_path):
            return {"error": "mitre_attack.json not found"}
            
        with open(mitre_path, "r") as f:
            tactics = json.load(f)
            
        heatmap = {}
        observed_ttps = [f.get("mitre_ttp") for f in findings if f.get("mitre_ttp")]
        
        for tactic, ttps in tactics.items():
            matches = [t for t in ttps if t in observed_ttps]
            coverage = (len(matches) / len(ttps)) * 100
            heatmap[tactic] = {
                "coverage_pct": coverage,
                "tested_ttps": matches,
                "missing_ttps": [t for t in ttps if t not in matches]
            }
            
        return heatmap

    def get_summary(self):
        summary = {
            "node_count": self.graph.number_of_nodes(),
            "edge_count": self.graph.number_of_edges(),
            "hosts": len(self.query_by_type("host")),
            "services": len(self.query_by_type("service")),
            "vulnerabilities": len(self.query_by_type("vulnerability"))
        }
        return summary
