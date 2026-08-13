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
