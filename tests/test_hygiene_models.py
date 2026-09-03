import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from hygiene.models import Finding, FixOption, PolicyFix, HygieneResult


def test_finding_round_trip():
    f = Finding(
        policy_id="12", policy_name="Allow X", seq=3, check="shadow",
        detail="shadowed by policy 5", severity="high",
        shadow_rule={"policy_id": "12"}, shadowing_rule={"policy_id": "5"},
        duplicate_of=None,
    )
    d = f.to_dict()
    assert d["policy_id"] == "12"
    assert d["shadow_rule"] == {"policy_id": "12"}
    assert d["duplicate_of"] is None


def test_fixoption_defaults():
    opt = FixOption(option_id="A", label="Disable", description="disable it")
    d = opt.to_dict()
    assert d["cli"] == []
    assert d["new_comment"] is None
    assert d["irreversible"] is False


def test_hygiene_result_to_dict_nests_fixes():
    fix = PolicyFix(policy_id="1", policy_name="P1", check="unhit",
                     options=[FixOption(option_id="A", label="Disable", description="d")])
    result = HygieneResult(device="FW1", adom="OT-ADOM", pkg="pkg1",
                            generated_at="2026-09-03T00:00:00", fixes=[fix],
                            stale_findings=[{"policy_id": "99", "reason": "gone"}])
    d = result.to_dict()
    assert d["fixes"][0]["options"][0]["label"] == "Disable"
    assert d["stale_findings"][0]["reason"] == "gone"
