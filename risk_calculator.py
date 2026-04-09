#!/usr/bin/env python3
import json
import random
from graph_manager import GraphManager

class RiskCalculator:
    def __init__(self):
        self.graph_manager = GraphManager()

    def calculate_exploit_risk(self, target: str, command: str, stealth: bool = False) -> dict:
        """
        Calculate the success probability and detection risk for a given offensive action.
        """
        # 1. Base Success Probability
        success_prob = 0.70 # Default 70%
        
        # 2. Base Detection Risk
        detection_risk = "Medium"
        
        # 3. Adjust for Stealth Mode
        if stealth:
            success_prob -= 0.15 # Stealth is slower/harder
            detection_risk = "Low"
        else:
            detection_risk = "High" if "msf" in command or "-A" in command else "Medium"

        # 4. Intelligence-based adjustments
        # Check if we have service info in the graph
        state = self.graph_manager.get_summary()
        if state["vulnerabilities"] > 0:
            success_prob += 0.10 # More info = higher success
            
        # 5. Tool-specific logic
        if "nmap" in command:
            success_prob = 0.95
            detection_risk = "Low" if "-T2" in command or stealth else "High"
        
        if "msf" in command:
            success_prob = 0.60 # Exploits are finicky
            
        # Clamp probability
        success_prob = max(0.1, min(0.99, success_prob))
        
        return {
            "success_probability": int(success_prob * 100),
            "detection_risk": detection_risk,
            "rationale": f"Based on {'stealth' if stealth else 'loud'} profile and target complexity."
        }
