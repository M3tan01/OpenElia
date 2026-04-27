#!/usr/bin/env python3
"""
llm_client.py — Unified LLM client factory for OpenElia.

Agents call LLMClient.create() to get a pre-configured AsyncOpenAI-compatible
client and the model name resolved by ModelManager.  They never need to know
whether they're hitting Ollama, OpenAI, Anthropic, or Google.

Usage:
    client, model, is_local = LLMClient.create(brain_tier="expensive", agent_name="Reporter")
    response = await client.chat.completions.create(model=model, ...)
"""

from openai import AsyncOpenAI
from model_manager import ModelManager


class LLMClient:
    @staticmethod
    def create(
        brain_tier: str = "local",
        agent_name: str | None = None,
    ) -> tuple[AsyncOpenAI, str, bool]:
        """
        Return (AsyncOpenAI client, model_name, is_local) resolved from ModelManager.

        Args:
            brain_tier:  "local" | "expensive" — backward-compat with existing agents.
            agent_name:  If set and hybrid mode is active, the per-agent override wins.
        """
        cfg = ModelManager.get_client_config(
            brain_tier=brain_tier,
            agent_name=agent_name,
        )
        client = AsyncOpenAI(
            base_url=cfg["base_url"],
            api_key=cfg["api_key"],
        )
        return client, cfg["model"], cfg.get("is_local", False)
