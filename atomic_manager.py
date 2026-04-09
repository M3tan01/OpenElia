#!/usr/bin/env python3
import json
import os

class AtomicManager:
    def __init__(self, definitions_path="skills/atomic/definitions.json"):
        self.definitions_path = definitions_path
        self.definitions = self._load()

    def _load(self):
        if os.path.exists(self.definitions_path):
            with open(self.definitions_path, "r") as f:
                return json.load(f)
        return {}

    def get_test(self, ttp_id, test_id=1):
        """Retrieve a specific atomic test by TTP ID and Test ID."""
        ttp = self.definitions.get(ttp_id)
        if not ttp:
            return None
        
        for test in ttp.get("tests", []):
            if test.get("id") == test_id:
                return {
                    "ttp_id": ttp_id,
                    "ttp_name": ttp.get("name"),
                    **test
                }
        return None

    def list_ttps(self):
        """List all supported TTP IDs and names."""
        return {ttp_id: data.get("name") for ttp_id, data in self.definitions.items()}

    def get_knowledge_summary(self):
        """Generate a compact summary for system prompt injection."""
        summary = "## Atomic Red Team Library (Validated Techniques)\n"
        for ttp_id, data in self.definitions.items():
            summary += f"- {ttp_id}: {data.get('name')}\n"
        summary += "\nUse 'mcp-atomic' to retrieve exact commands for these TTPs."
        return summary
