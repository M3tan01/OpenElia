import json
import os

class AdversaryManager:
    def __init__(self, adversaries_dir="adversaries"):
        self.adversaries_dir = adversaries_dir

    def load_profile(self, apt_name: str) -> dict:
        """Load a specific APT JSON profile."""
        profile_path = os.path.join(self.adversaries_dir, f"{apt_name.lower()}.json")
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
