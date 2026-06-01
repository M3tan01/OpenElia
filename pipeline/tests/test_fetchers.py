"""Mock-mode fetcher + stage-runner shape tests (no network)."""
import os
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import run_stage  # noqa: E402
from fetchers import ioc_feed, log_source, siem_feed  # noqa: E402


def test_fetchers_mock_nonempty():
    assert ioc_feed.fetch("mock")
    assert siem_feed.fetch("mock")
    assert log_source.fetch("mock")


def test_fetchers_bad_mode_raises():
    for mod in (ioc_feed, siem_feed, log_source):
        with pytest.raises(ValueError):
            mod.fetch("bogus")


def test_fetchers_live_stubbed():
    for mod in (ioc_feed, siem_feed, log_source):
        with pytest.raises(NotImplementedError):
            mod.fetch("live")


def test_run_ioc_carries_disposition_and_verdict():
    records, meta = run_stage.run_ioc("mock")
    assert records and all("disposition" in r for r in records)
    assert all("feed_source" in r for r in records)
    assert meta["verdict"] in ("BLOCK", "MONITOR", "INVESTIGATE")
    assert "dispositions" in meta


def test_run_triage_maps_techniques():
    events, meta = run_stage.run_triage("mock")
    # the powershell -enc / kerberoast fixtures must produce technique hits
    assert meta["techniques"]
    assert any("T1059.001" in t for t in meta["techniques"])
    assert any("T1558.003" in t for t in meta["techniques"])
    assert meta["severity"] == "high"
    assert all("techniques" in ev for ev in events)


def test_run_siem_buckets_severity():
    alerts, meta = run_stage.run_siem("mock")
    assert meta["result_count"] == len(alerts)
    assert meta["top_severity"] == "high"
    assert sum(meta["by_severity"].values()) == len(alerts)


def test_emit_roundtrip(tmp_path, monkeypatch):
    import emit
    monkeypatch.setattr(emit, "_STAGING_DIR", str(tmp_path))
    records, meta = run_stage.run_siem("mock")
    path = emit.write("siem", records, "mock", meta=meta)
    assert os.path.exists(path)
    assert emit.latest("siem") == path
