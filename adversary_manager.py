import json
import os
import re

class AdversaryManager:
    _APT_NAME_RE = re.compile(r"^[a-z0-9_-]{1,32}$")

    def __init__(self, adversaries_dir="adversaries"):
        self.adversaries_dir = os.path.realpath(adversaries_dir)

    def load_profile(self, apt_name: str) -> dict:
        """Load a specific APT JSON profile."""
        safe_name = apt_name.lower()
        if not self._APT_NAME_RE.fullmatch(safe_name):
            raise ValueError(f"Invalid APT profile name: '{apt_name}'")
        profile_path = os.path.realpath(os.path.join(self.adversaries_dir, f"{safe_name}.json"))
        if not profile_path.startswith(self.adversaries_dir + os.sep):
            raise ValueError("Path traversal detected in APT profile name.")
        if os.path.exists(profile_path):
            with open(profile_path, "r") as f:
                return json.load(f)
        return {}

    def get_persona_prompt(self, apt_name: str) -> str:
        """Generate a system prompt block for the selected adversary."""
        profile = self.load_profile(apt_name)
        if not profile:
            return ""
            
        prompt = (
            f"\n\n=== !!! ADVERSARY PERSONA: {profile['name']} ({profile['alias']}) !!! ===\n"
            f"Description: {profile['description']}\n"
            f"Target Methodology: {profile['rationale']}\n"
            f"Preferred TTPs: {', '.join(profile['preferred_ttps'])}\n"
            f"Allowed Tools: {', '.join(profile['tools'])}\n"
        )
        
        if profile.get("stealth_required"):
            prompt += "MANDATE: This adversary operates with extreme stealth. Priority is evasion over speed.\n"
            
        return prompt
