"""Test campaign_id field in PurpleRun control model."""
from webdash.api.control import PurpleRun


def test_purplerun_accepts_campaign_id():
    """Verify PurpleRun can accept and retain campaign_id."""
    r = PurpleRun(target="10.0.0.1", campaign_id="C1", confirm=True)
    assert r.campaign_id == "C1"


def test_purplerun_campaign_id_defaults_none():
    """Verify campaign_id defaults to None when not provided."""
    r = PurpleRun(target="10.0.0.1", confirm=True)
    assert r.campaign_id is None
