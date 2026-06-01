"""
Tests for core.loop_guard — the agent tool-loop guardrail.

Pure synchronous logic (no event loop, no LLM). Covers the three failure modes,
the disabled passthrough, config construction, and the ModelManager wiring.
"""
import pytest

from core.loop_guard import (
    DEFAULT_IDEMPOTENT_TOOLS,
    LoopDecision,
    LoopGuard,
    LoopGuardConfig,
)


# --------------------------------------------------------------------------- #
# Disabled passthrough                                                         #
# --------------------------------------------------------------------------- #

def test_disabled_guard_always_returns_ok():
    # Arrange
    guard = LoopGuard(LoopGuardConfig(enabled=False, max_total_turns=1))
    # Act / Assert — well past every ceiling, still ok
    for _ in range(10):
        assert guard.observe("read_state", {}, "same") == LoopDecision("ok", "")


# --------------------------------------------------------------------------- #
# Repeated identical (tool, args) call                                         #
# --------------------------------------------------------------------------- #

def test_repeated_identical_call_warns_then_blocks():
    # Arrange — non-idempotent tool so only the same-call rule is in play
    guard = LoopGuard(LoopGuardConfig(max_same_call=3))
    args = {"target": "10.0.0.5"}

    # Act / Assert
    assert guard.observe("nmap", args, "open: 80").action == "ok"      # count 1
    assert guard.observe("nmap", args, "open: 80").action == "warn"    # count 2 (3-1)
    blocked = guard.observe("nmap", args, "open: 80")                  # count 3
    assert blocked.is_block
    assert "repeated 3 times" in blocked.rationale


def test_distinct_calls_never_trip():
    # Arrange
    guard = LoopGuard(LoopGuardConfig(max_same_call=2, max_total_turns=100))
    # Act / Assert — different args each turn resets the consecutive counter
    for i in range(20):
        assert guard.observe("nmap", {"target": f"10.0.0.{i}"}, f"r{i}").action == "ok"


def test_same_call_counter_resets_on_different_call():
    # Arrange
    guard = LoopGuard(LoopGuardConfig(max_same_call=2))
    # Act — A then B then A: never two A's in a row
    assert guard.observe("nmap", {"t": "a"}, "x").action == "ok"
    assert guard.observe("nmap", {"t": "b"}, "x").action == "ok"
    # Assert — back to A is count 1 again, not a block
    assert guard.observe("nmap", {"t": "a"}, "x").action == "ok"


def test_args_key_is_order_independent():
    # Arrange
    guard = LoopGuard(LoopGuardConfig(max_same_call=2))
    # Act — same dict, different key insertion order -> same identity
    first = guard.observe("nmap", {"a": 1, "b": 2}, "r")
    second = guard.observe("nmap", {"b": 2, "a": 1}, "r")
    # Assert — second is treated as a repeat (count 2 == block at limit 2)
    assert first.action == "ok"
    assert second.is_block


# --------------------------------------------------------------------------- #
# Absolute turn ceiling                                                        #
# --------------------------------------------------------------------------- #

def test_turn_ceiling_blocks_after_limit():
    # Arrange — distinct calls so only the turn ceiling can fire
    guard = LoopGuard(LoopGuardConfig(max_total_turns=5, max_same_call=99))

    # Act — 5 distinct calls are fine
    for i in range(5):
        assert guard.observe("nmap", {"t": i}, f"r{i}").action == "ok"

    # Assert — the 6th trips the hard cap
    blocked = guard.observe("nmap", {"t": 99}, "r99")
    assert blocked.is_block
    assert "turn ceiling" in blocked.rationale


# --------------------------------------------------------------------------- #
# Idempotent-result spinning                                                   #
# --------------------------------------------------------------------------- #

def test_idempotent_tool_identical_result_blocks():
    # Arrange — vary args so the same-call rule cannot fire; isolate idempotent rule
    guard = LoopGuard(LoopGuardConfig(max_idempotent_repeats=2, max_same_call=99))

    # Act
    first = guard.observe("read_state", {"k": 1}, "STATE_BLOB")
    second = guard.observe("read_state", {"k": 2}, "STATE_BLOB")

    # Assert — identical result twice trips the idempotent rule at limit 2
    assert first.action == "ok"
    assert second.is_block
    assert "idempotent tool 'read_state'" in second.rationale


def test_idempotent_tool_changing_result_does_not_block():
    # Arrange
    guard = LoopGuard(LoopGuardConfig(max_idempotent_repeats=2, max_same_call=99))
    # Act / Assert — different result each turn keeps the count at 1
    for i in range(10):
        assert guard.observe("read_state", {"k": i}, f"state-{i}").action == "ok"


def test_non_idempotent_tool_repeating_result_not_subject_to_idempotent_rule():
    # Arrange — 'nmap' is not idempotent; identical result must not trip rule #3
    guard = LoopGuard(LoopGuardConfig(max_idempotent_repeats=2, max_same_call=99))
    # Act / Assert — vary args (avoid same-call), identical results -> still ok
    for i in range(10):
        assert guard.observe("nmap", {"t": i}, "IDENTICAL").action == "ok"


# --------------------------------------------------------------------------- #
# Simulated loop — proves the contract base_agent relies on                    #
# --------------------------------------------------------------------------- #

def test_simulated_runaway_loop_is_halted():
    # Arrange — an idempotent tool called identically forever (the real bug shape)
    guard = LoopGuard(LoopGuardConfig())
    args = {}
    decisions = [guard.observe("read_state", args, "SAME") for _ in range(50)]
    # Assert — a block is emitted well before 50 iterations
    assert any(d.is_block for d in decisions)
    first_block = next(i for i, d in enumerate(decisions) if d.is_block)
    assert first_block < LoopGuardConfig().max_total_turns


# --------------------------------------------------------------------------- #
# Config construction                                                          #
# --------------------------------------------------------------------------- #

def test_from_mapping_uses_defaults_when_empty():
    cfg = LoopGuardConfig.from_mapping(None)
    assert cfg.enabled is True
    assert cfg.max_total_turns == 25
    assert cfg.max_same_call == 3
    assert cfg.max_idempotent_repeats == 2
    assert cfg.idempotent_tools == DEFAULT_IDEMPOTENT_TOOLS


def test_from_mapping_overrides_and_custom_tools():
    cfg = LoopGuardConfig.from_mapping(
        {
            "enabled": False,
            "max_total_turns": 7,
            "max_same_call": 2,
            "max_idempotent_repeats": 4,
            "idempotent_tools": ["foo", "bar"],
        }
    )
    assert cfg.enabled is False
    assert cfg.max_total_turns == 7
    assert cfg.max_same_call == 2
    assert cfg.max_idempotent_repeats == 4
    assert cfg.idempotent_tools == frozenset({"foo", "bar"})


def test_loop_decision_properties():
    assert LoopDecision("block", "x").is_block is True
    assert LoopDecision("warn", "x").is_warn is True
    assert LoopDecision("ok", "").is_block is False
    assert LoopDecision("ok", "").is_warn is False


# --------------------------------------------------------------------------- #
# ModelManager wiring                                                          #
# --------------------------------------------------------------------------- #

def test_get_loop_config_reads_defaults(monkeypatch):
    from model_manager import ModelManager, _DEFAULTS

    monkeypatch.delenv("OPENELIA_LOOP_DETECTION_ENABLED", raising=False)
    monkeypatch.setattr(ModelManager, "_load", classmethod(lambda cls: dict(_DEFAULTS)))

    cfg = ModelManager.get_loop_config()
    assert cfg.enabled is True
    assert cfg.max_total_turns == 25


def test_get_loop_config_env_override_disables(monkeypatch):
    from model_manager import ModelManager, _DEFAULTS

    monkeypatch.setattr(ModelManager, "_load", classmethod(lambda cls: dict(_DEFAULTS)))
    monkeypatch.setenv("OPENELIA_LOOP_DETECTION_ENABLED", "0")

    cfg = ModelManager.get_loop_config()
    assert cfg.enabled is False


def test_get_loop_config_env_override_enables(monkeypatch):
    from model_manager import ModelManager

    # Persisted config says disabled; env forces it back on.
    monkeypatch.setattr(
        ModelManager, "_load", classmethod(lambda cls: {"loop_detection": {"enabled": False}})
    )
    monkeypatch.setenv("OPENELIA_LOOP_DETECTION_ENABLED", "true")

    cfg = ModelManager.get_loop_config()
    assert cfg.enabled is True
