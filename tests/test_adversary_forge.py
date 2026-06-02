from graph_manager import GraphManager


def test_detected_os_collects_lowercased_host_os(tmp_path):
    gm = GraphManager(db_path=str(tmp_path / "g.json"))
    gm.add_host("10.0.0.5", os="Windows")
    gm.add_host("10.0.0.6", os="linux")
    gm.add_host("10.0.0.7")  # os is None -> skipped
    assert gm.detected_os() == {"windows", "linux"}


def test_detected_os_empty_when_no_os_known(tmp_path):
    gm = GraphManager(db_path=str(tmp_path / "g.json"))
    gm.add_host("10.0.0.5")
    assert gm.detected_os() == set()


import json
import pytest
from adversary_schema import AdversaryProfile, save_profile


def test_profile_requires_core_fields():
    with pytest.raises(Exception):
        AdversaryProfile(name="x")  # missing required fields


def test_profile_roundtrips_existing_schema():
    p = AdversaryProfile(
        name="APT29", alias="Cozy Bear", description="d",
        preferred_ttps=["T1059.001"], tools=["powershell"],
        stealth_required=True, rationale="r",
    )
    d = p.model_dump()
    assert set(d) == {"name", "alias", "description", "preferred_ttps",
                      "tools", "stealth_required", "rationale"}


def test_save_profile_writes_into_adversaries_dir(tmp_path):
    p = AdversaryProfile(
        name="TEST", alias="t", description="d",
        preferred_ttps=["T1059"], tools=["nmap"],
        stealth_required=False, rationale="r",
    )
    path = save_profile(p, "tailored_test", adversaries_dir=str(tmp_path))
    on_disk = json.loads((tmp_path / "tailored_test.json").read_text())
    assert on_disk["name"] == "TEST"
    assert path.endswith("tailored_test.json")


def test_save_profile_blocks_path_traversal(tmp_path):
    p = AdversaryProfile(
        name="TEST", alias="t", description="d",
        preferred_ttps=[], tools=[], stealth_required=False, rationale="r",
    )
    with pytest.raises(ValueError):
        save_profile(p, "../evil", adversaries_dir=str(tmp_path))
