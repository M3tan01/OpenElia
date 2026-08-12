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
