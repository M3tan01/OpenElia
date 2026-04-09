#!/usr/bin/env python3
import json
import os
from datetime import datetime
from rich.console import Console

console = Console()

# Standard pricing estimates (per 1M tokens) - can be updated via env
PRICING = {
    "claude-3-5-sonnet-20241022": {"input": 3.00, "output": 15.00},
    "gpt-4o": {"input": 5.00, "output": 15.00},
    "gpt-4o-mini": {"input": 0.15, "output": 0.60},
    "llama3.1:8b": {"input": 0.00, "output": 0.00}, # Local is free
    "default": {"input": 10.00, "output": 30.00}
}

class CostTracker:
    def __init__(self, log_path="state/costs.json"):
        self.log_path = log_path
        os.makedirs(os.path.dirname(self.log_path), exist_ok=True)
        self.session_id = datetime.utcnow().strftime("%Y%m%d_%H%M")
        # Global budget limit in USD
        self.max_budget = float(os.getenv("MAX_TOKEN_BUDGET", "5.00"))

    def _load_history(self):
        if os.path.exists(self.log_path):
            try:
                with open(self.log_path, "r") as f:
                    return json.load(f)
            except:
                return {}
        return {}

    def _save_history(self, history):
        with open(self.log_path, "w") as f:
            json.dump(history, f, indent=2)

    def track_usage(self, model: str, input_tokens: int, output_tokens: int):
        history = self._load_history()
        
        pricing = PRICING.get(model, PRICING["default"])
        cost = (input_tokens / 1_000_000 * pricing["input"]) + (output_tokens / 1_000_000 * pricing["output"])
        
        entry = history.get(self.session_id, {"total_cost": 0.0, "calls": 0})
        entry["total_cost"] += cost
        entry["calls"] += 1
        
        history[self.session_id] = entry
        self._save_history(history)
        
        # Total cost across all sessions tracked in this log
        total_historical_cost = sum(item["total_cost"] for item in history.values())
        
        if total_historical_cost > self.max_budget:
            console.print(f"\n[bold red]🛑 TOKEN BUDGET EXCEEDED![/bold red]")
            console.print(f"Current Spend: ${total_historical_cost:.4f} | Limit: ${self.max_budget:.2f}")
            raise PermissionError(f"Token Budget Exceeded (${total_historical_cost:.4f}). Execution halted to prevent runaway costs.")
            
        return cost, total_historical_cost

    def get_summary(self):
        history = self._load_history()
        total = sum(item["total_cost"] for item in history.values())
        return {
            "session_cost": history.get(self.session_id, {}).get("total_cost", 0.0),
            "total_historical_cost": total,
            "budget_remaining": self.max_budget - total
        }
