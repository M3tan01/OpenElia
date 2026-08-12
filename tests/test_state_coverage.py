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
