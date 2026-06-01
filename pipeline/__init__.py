"""OpenElia scheduled security/forensics pipeline.

Deterministic fetch + enrich layer for the hybrid pipeline. Each stage pulls
data (mock fixtures or live sources), normalizes/enriches it, and writes a
staging JSON blob that the Claude-native cron commands consume to produce
Obsidian vault notes.

Stages: ioc | triage | siem  (see run_stage.py).
"""

__all__ = ["enrichers", "emit", "fetchers"]
