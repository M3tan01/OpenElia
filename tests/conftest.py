import sys
import os
import json

import pytest

# Make the project root importable regardless of where pytest is invoked from.
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))


@pytest.fixture(autouse=True)
def _seed_model_config(tmp_path, monkeypatch):
    """Isolate ModelManager config to a temp dir with a model already configured.

    OpenElia ships no default model name — resolving one when none is set raises
    ModelNotConfiguredError (by design). Agent tests construct real agents, which
    resolve a model at __init__, so the test environment must supply one just as
    a real operator would via `model set local/cloud`.

    Files that specifically test the no-model behavior (test_model_manager.py)
    define their own module-scoped autouse fixture that re-points the config path
    *after* this one runs, giving them a clean, empty config.
    """
    import model_manager as mm

    cfg_dir = tmp_path / "mm-config"
    cfg_dir.mkdir()
    cfg_file = cfg_dir / "config.json"
    cfg_file.write_text(json.dumps({
        "mode":            "local",
        "local_model":     "test-local:latest",
        "cloud_provider":  "openai",
        "cloud_model":     "test-cloud",
        "agent_overrides": {},
    }))
    monkeypatch.setattr(mm, "_CONFIG_DIR", cfg_dir)
    monkeypatch.setattr(mm, "_CONFIG_FILE", cfg_file)
    yield


@pytest.fixture(autouse=True)
def _isolate_state_dir(tmp_path, monkeypatch):
    """Redirect the lifecycle hooks' state dir into a per-test tmp sandbox.

    core.hooks._state_dir() resolves Path(os.getenv("STATE_DIR", "state")) at
    call time, so post_run_hook / error_hook otherwise append to the *live*
    state/audit.log (HMAC-chained) and state/task_results.jsonl. Tests that
    exercise _dispatch_task or the hooks directly (test_orchestrator_pool,
    test_purple_loop, test_worker_pool) were leaking synthetic 'agent exploded'
    records into the production audit trail. Isolating STATE_DIR here keeps every
    test's hook writes inside tmp_path.
    """
    # Distinct name (not "state") so it never collides with tests that create
    # their own tmp_path/state — e.g. test_rbac_manager chdir's into tmp_path and
    # mkdir's ./state, which would FileExistsError if we pre-created it here.
    state_dir = tmp_path / "_hook_state"
    state_dir.mkdir()
    # Two env names are in play across the codebase: core.hooks resolves STATE_DIR,
    # while the audit-domain writers (AuditLogger, webdash/guards, mcp siem) resolve
    # OPENELIA_STATE_DIR. Set both so every audit/task-result writer lands in tmp.
    monkeypatch.setenv("STATE_DIR", str(state_dir))
    monkeypatch.setenv("OPENELIA_STATE_DIR", str(state_dir))
    yield
