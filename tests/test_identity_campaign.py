from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource

from lurescope.cli import main
from lurescope.identity_campaign import (
    CHECK_NAMES,
    create_identity_campaign_verification,
    derive_identity_campaign_plan,
    load_identity_campaign_verification,
    validate_identity_campaign_verification,
)

ROOT = Path(__file__).parents[1]
VECTOR = ROOT / "conformance" / "lureidentity-campaign-v1"


def _load(name: str) -> dict:
    return json.loads((VECTOR / name).read_text(encoding="utf-8"))


def _schema(filename: str, value: dict) -> None:
    resources = []
    for path in (ROOT / "spec").glob("*.json"):
        schema = json.loads(path.read_text(encoding="utf-8"))
        if "$id" in schema:
            resources.append((schema["$id"], Resource.from_contents(schema)))
    registry = Registry().with_resources(resources)
    schema = json.loads((ROOT / "spec" / filename).read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(
        schema, registry=registry, format_checker=FormatChecker()
    ).validate(value)


def _write(path: Path, value: dict) -> None:
    path.write_text(json.dumps(value), encoding="utf-8")


def test_independent_compiler_matches_public_cross_repository_vector():
    campaign = _load("campaign.json")
    expected = _load("plan.json")
    _schema("lureidentity-campaign-v1.schema.json", campaign)
    assert derive_identity_campaign_plan(campaign) == expected
    source = (ROOT / "lurescope" / "identity_campaign.py").read_text(encoding="utf-8")
    assert "import lurebench" not in source
    assert "from lurebench" not in source


def test_campaign_verification_is_self_contained_schema_valid_and_recomputable(
    tmp_path: Path,
):
    campaign_path = tmp_path / "campaign.json"
    plan_path = tmp_path / "plan.json"
    report_path = tmp_path / "verification.json"
    _write(campaign_path, _load("campaign.json"))
    _write(plan_path, _load("plan.json"))
    report = create_identity_campaign_verification(
        campaign_path,
        plan_path,
        report_path,
        verified_at="2026-09-03T12:00:00Z",
    )
    _schema("lureidentity-campaign-verification-v1.schema.json", report)
    assert validate_identity_campaign_verification(report) == report
    assert load_identity_campaign_verification(report_path) == report
    assert [item["check"] for item in report["checks"]] == CHECK_NAMES
    assert report["summary"] == {
        "principal_count": 7,
        "authority_edge_count": 6,
        "grant_count": 1,
        "event_count": 1,
        "node_count": 2,
        "cut_authorization_count": 3,
        "preserved_authorization_count": 4,
        "probe_count": 26,
    }
    if os.name == "posix":
        assert report_path.stat().st_mode & 0o777 == 0o600


def test_verifier_rejects_plan_and_self_contained_report_tampering(tmp_path: Path):
    campaign_path = tmp_path / "campaign.json"
    plan_path = tmp_path / "plan.json"
    _write(campaign_path, _load("campaign.json"))
    tampered_plan = _load("plan.json")
    tampered_plan["probes"][0]["attempted_at_ms"] += 1
    _write(plan_path, tampered_plan)
    with pytest.raises(ValueError, match="exact independently derived"):
        create_identity_campaign_verification(campaign_path, plan_path)

    _write(plan_path, _load("plan.json"))
    report = create_identity_campaign_verification(
        campaign_path, plan_path, verified_at="2026-09-03T12:00:00Z"
    )
    report["summary"]["probe_count"] -= 1
    with pytest.raises(ValueError, match="does not independently recompute"):
        validate_identity_campaign_verification(report)

    report = create_identity_campaign_verification(
        campaign_path, plan_path, verified_at="2026-09-03T12:00:00Z"
    )
    report["campaign"]["probe_schedule"]["post_deadline_offset_ms"] += 1
    with pytest.raises(ValueError, match="does not independently recompute"):
        validate_identity_campaign_verification(report)


def test_identity_verify_campaign_cli_never_overwrites(tmp_path: Path, capsys):
    campaign_path = tmp_path / "campaign.json"
    plan_path = tmp_path / "plan.json"
    report_path = tmp_path / "verification.json"
    _write(campaign_path, _load("campaign.json"))
    _write(plan_path, _load("plan.json"))
    command = [
        "identity",
        "verify-campaign",
        str(campaign_path),
        str(plan_path),
        "--verified-at",
        "2026-09-03T12:00:00Z",
        "--out",
        str(report_path),
    ]
    assert main(command) == 0
    assert "LUREIDENTITY CAMPAIGN VERIFIED" in capsys.readouterr().out
    original = report_path.read_bytes()
    assert main(command) == 2
    assert report_path.read_bytes() == original


def test_independent_compiler_rejects_unknown_and_unbounded_campaigns():
    campaign = _load("campaign.json")
    campaign["unknown"] = True
    with pytest.raises(ValueError, match="field allowlist"):
        derive_identity_campaign_plan(campaign)

    campaign = _load("campaign.json")
    campaign["probe_schedule"]["propagation_probe_offset_ms"] = 500
    with pytest.raises(ValueError, match="shorter than"):
        derive_identity_campaign_plan(campaign)

    campaign = _load("campaign.json")
    campaign["events"][0]["event_type"] = "unknown"
    with pytest.raises(ValueError, match="unsupported"):
        derive_identity_campaign_plan(campaign)
