import os
import tempfile

from state_manager import StateManager


def _fresh_state() -> StateManager:
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    return StateManager(db_path=path)


def test_add_blue_alert_persists_mitre_ttp():
    st = _fresh_state()
    eid = st.initialize_engagement(target="10.0.0.1", scope="unit")["engagement"]["id"]
    st.add_blue_alert(
        alert_type="LSASS_ACCESS",
        description="handle to lsass",
        severity="high",
        source="defender_mon",
        engagement_id=eid,
        mitre_ttp="T1003.001",
    )
    alerts = st.read(eid)["blue_alerts"]
    assert alerts[0]["mitre_ttp"] == "T1003.001"


def test_add_blue_alert_without_mitre_ttp_defaults_null():
    st = _fresh_state()
    eid = st.initialize_engagement(target="10.0.0.1", scope="unit")["engagement"]["id"]
    st.add_blue_alert(
        alert_type="GENERIC",
        description="no technique",
        severity="low",
        source="defender_hunt",
        engagement_id=eid,
    )
    alerts = st.read(eid)["blue_alerts"]
    assert alerts[0]["mitre_ttp"] is None


def _seed(st, eid, *, findings, alerts, blue_status):
    for ttp, title in findings:
        st.add_finding(
            severity="high", title=title, description="d", evidence="e",
            mitre_ttp=ttp, source_agent="pentester_ex", engagement_id=eid,
        )
    for ttp in alerts:
        st.add_blue_alert(
            alert_type="A", description="d", severity="high",
            source="defender_mon", engagement_id=eid, mitre_ttp=ttp,
        )
    if blue_status is not None:
        st.set_metadata("blue_run_status", blue_status, eid)


def test_caught_when_alert_matches_and_blue_complete():
    st = _fresh_state()
    st.initialize_engagement(target="t", scope="u")
    eid = st.active_engagement_id
    _seed(st, eid, findings=[("T1003", "LSASS")], alerts=["T1003"], blue_status="complete")
    cov = st.get_coverage(eid)
    assert [c["ttp"] for c in cov["caught"]] == ["T1003"]
    assert cov["missed"] == [] and cov["pending"] == []


def test_missed_when_no_alert_and_blue_complete():
    st = _fresh_state()
    st.initialize_engagement(target="t", scope="u")
    eid = st.active_engagement_id
    _seed(st, eid, findings=[("T1490", "VSS delete")], alerts=[], blue_status="complete")
    cov = st.get_coverage(eid)
    assert [m["ttp"] for m in cov["missed"]] == ["T1490"]
    assert cov["caught"] == [] and cov["pending"] == []


def test_pending_when_no_alert_and_blue_running():
    st = _fresh_state()
    st.initialize_engagement(target="t", scope="u")
    eid = st.active_engagement_id
    _seed(st, eid, findings=[("T1071.001", "C2 beacon")], alerts=[], blue_status="running")
    cov = st.get_coverage(eid)
    assert [p["ttp"] for p in cov["pending"]] == ["T1071"]
    assert cov["missed"] == []


def test_base_technique_normalization_matches_subtechnique():
    st = _fresh_state()
    st.initialize_engagement(target="t", scope="u")
    eid = st.active_engagement_id
    _seed(st, eid, findings=[("T1003.001", "LSASS")], alerts=["T1003"], blue_status="complete")
    cov = st.get_coverage(eid)
    assert len(cov["caught"]) == 1 and cov["missed"] == []


def test_coverage_pct_excludes_pending_and_zero_resolved():
    st = _fresh_state()
    st.initialize_engagement(target="t", scope="u")
    eid = st.active_engagement_id
    _seed(
        st, eid,
        findings=[("T1003", "a"), ("T1490", "b"), ("T1071.001", "c")],
        alerts=["T1003"], blue_status="running",
    )
    # blue still running: T1003 caught, others pending, none missed -> 1/(1+0)=100
    cov = st.get_coverage(eid)
    assert cov["coverage_pct"] == 100.0

    st.initialize_engagement(target="t", scope="u")
    eid2 = st.active_engagement_id
    _seed(st, eid2, findings=[], alerts=[], blue_status=None)
    assert st.get_coverage(eid2)["coverage_pct"] == 0


class _RecordingState:
    def __init__(self):
        self.calls = []

    def add_blue_alert(self, **kwargs):
        self.calls.append(kwargs)


def test_defender_mon_passes_rule_mitre_to_alert():
    from agents.blue.defender_mon import DefenderMon

    st = _RecordingState()
    mon = DefenderMon(st)
    # T1003_LSASS_ACCESS rule requires both patterns to match (AND logic).
    log_text = "TargetImage=C:\\Windows\\System32\\lsass.exe EventCode=10"
    mon.analyze(log_text)

    assert st.calls, "expected add_blue_alert to be called"
    assert st.calls[0]["mitre_ttp"] == "T1003.001"


def test_defender_hunt_passes_tool_mitre_to_alert():
    from agents.blue.defender_hunt import DefenderHunt

    st = _RecordingState()
    hunt = object.__new__(DefenderHunt)
    hunt.state = st

    hunt._execute_hunt_tool(
        "record_persistence_finding",
        {
            "mechanism": "cron",
            "location": "/etc/cron.d/x",
            "evidence": "x",
            "severity": "high",
            "mitre_ttp": "T1547.001",
        },
    )

    assert st.calls[0]["mitre_ttp"] == "T1547.001"


def test_add_response_action_persists_mitre_ttp():
    st = _fresh_state()
    st.initialize_engagement(target="t", scope="u")
    eid = st.active_engagement_id
    st.add_response_action(
        {"action_type": "block_ip", "target": "10.0.0.5", "command": "iptables -I INPUT -s 10.0.0.5 -j DROP",
         "rationale": "C2", "mitre_ttp": "T1071.001"},
        engagement_id=eid,
    )
    ras = st.read(eid)["response_actions"]
    assert ras[0]["mitre_ttp"] == "T1071.001"


def test_add_response_action_without_mitre_ttp_defaults_null():
    st = _fresh_state()
    st.initialize_engagement(target="t", scope="u")
    eid = st.active_engagement_id
    st.add_response_action(
        {"action_type": "other", "target": "host", "command": "noop", "rationale": "r"},
        engagement_id=eid,
    )
    assert st.read(eid)["response_actions"][0]["mitre_ttp"] is None


def _first_alert_id(st, eid):
    return st.read(eid)["blue_alerts"][0]["id"]


def _rung_of(cov, ttp):
    return next(e["rung"] for e in cov["scorecard"] if e["ttp"] == ttp)


def test_rung_prevented_when_response_matches():
    st = _fresh_state()
    st.initialize_engagement(target="t", scope="u")
    eid = st.active_engagement_id
    _seed(st, eid, findings=[("T1071.001", "C2")], alerts=["T1071"], blue_status="complete")
    st.add_response_action(
        {"action_type": "block_ip", "target": "1.1.1.1", "command": "iptables -I INPUT -s 1.1.1.1 -j DROP",
         "rationale": "r", "mitre_ttp": "T1071"},
        engagement_id=eid,
    )
    cov = st.get_coverage(eid)
    assert _rung_of(cov, "T1071") == "PREVENTED"


def test_rung_alerted_when_alert_escalated():
    st = _fresh_state()
    st.initialize_engagement(target="t", scope="u")
    eid = st.active_engagement_id
    _seed(st, eid, findings=[("T1003", "LSASS")], alerts=["T1003"], blue_status="complete")
    st.mark_alert_escalated(_first_alert_id(st, eid), eid)
    cov = st.get_coverage(eid)
    assert _rung_of(cov, "T1003") == "ALERTED"


def test_rung_detected_when_alert_unescalated_no_analysis():
    st = _fresh_state()
    st.initialize_engagement(target="t", scope="u")
    eid = st.active_engagement_id
    _seed(st, eid, findings=[("T1003", "LSASS")], alerts=["T1003"], blue_status="complete")
    cov = st.get_coverage(eid)
    assert _rung_of(cov, "T1003") == "DETECTED"


def test_rung_logged_when_dismissing_analysis_present():
    st = _fresh_state()
    st.initialize_engagement(target="t", scope="u")
    eid = st.active_engagement_id
    _seed(st, eid, findings=[("T1003", "LSASS")], alerts=["T1003"], blue_status="complete")
    aid = _first_alert_id(st, eid)
    st.add_blue_analysis({"alert_id": aid, "verdict": "fp", "escalate": False}, engagement_id=eid)
    cov = st.get_coverage(eid)
    assert _rung_of(cov, "T1003") == "LOGGED"


def test_rung_missed_when_blue_complete_no_signal():
    st = _fresh_state()
    st.initialize_engagement(target="t", scope="u")
    eid = st.active_engagement_id
    _seed(st, eid, findings=[("T1490", "VSS")], alerts=[], blue_status="complete")
    cov = st.get_coverage(eid)
    assert _rung_of(cov, "T1490") == "MISSED"


def test_rung_pending_when_blue_running_no_signal():
    st = _fresh_state()
    st.initialize_engagement(target="t", scope="u")
    eid = st.active_engagement_id
    _seed(st, eid, findings=[("T1490", "VSS")], alerts=[], blue_status="running")
    cov = st.get_coverage(eid)
    assert _rung_of(cov, "T1490") == "PENDING"


def test_rung_counts_and_sort_order():
    st = _fresh_state()
    st.initialize_engagement(target="t", scope="u")
    eid = st.active_engagement_id
    _seed(st, eid, findings=[("T1003", "a"), ("T1490", "b")], alerts=["T1003"], blue_status="complete")
    cov = st.get_coverage(eid)
    assert cov["rung_counts"]["DETECTED"] == 1
    assert cov["rung_counts"]["MISSED"] == 1
    # sorted by precedence desc: DETECTED(3) before MISSED(1)
    assert [e["ttp"] for e in cov["scorecard"]] == ["T1003", "T1490"]


def test_time_to_detect_none_when_no_alert():
    st = _fresh_state()
    st.initialize_engagement(target="t", scope="u")
    eid = st.active_engagement_id
    _seed(st, eid, findings=[("T1490", "b")], alerts=[], blue_status="complete")
    cov = st.get_coverage(eid)
    assert next(e for e in cov["scorecard"] if e["ttp"] == "T1490")["time_to_detect_s"] is None


def test_time_to_detect_clamps_and_computes():
    from state_manager import _ttd_seconds
    assert _ttd_seconds("2026-09-07T10:00:00+00:00", "2026-09-07T10:00:30+00:00") == 30
    assert _ttd_seconds("2026-09-07T10:00:30+00:00", "2026-09-07T10:00:00+00:00") == 0  # clock-skew clamp
    assert _ttd_seconds("garbage", "2026-09-07T10:00:00+00:00") is None


def test_legacy_db_gains_response_actions_mitre_ttp_column():
    import sqlite3 as _sq, os as _os, tempfile as _tf
    fd, path = _tf.mkstemp(suffix=".db")
    _os.close(fd)
    # Simulate a pre-migration DB: response_actions without mitre_ttp.
    conn = _sq.connect(path)
    conn.execute(
        "CREATE TABLE response_actions (id INTEGER PRIMARY KEY AUTOINCREMENT, engagement_id TEXT, "
        "action_type TEXT, target TEXT, command TEXT, rationale TEXT, requires_approval INTEGER, logged_at TEXT)"
    )
    conn.commit()
    conn.close()
    # Opening via StateManager must run the idempotent migration without error.
    st = StateManager(db_path=path)
    cols = {row[1] for row in _sq.connect(path).execute("PRAGMA table_info(response_actions)").fetchall()}
    assert "mitre_ttp" in cols
