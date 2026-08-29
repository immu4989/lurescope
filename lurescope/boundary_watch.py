"""Anytime-valid drift monitoring for disjoint scheduled LureBoundary probes."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any, Dict, Optional

from .agent_assurance import _load_evidence
from .boundary import load_boundary_evaluation
from .watch import (
    MonitorCount,
    MonitorSpec,
    _load_plan,
    append_monitor_batch,
    create_monitor_bundle,
)

PROBE_MISS = "boundary.probe-miss"
BENIGN_FALSE_ALARM = "boundary.benign-false-alarm"
LINEAGE_FAILURE = "boundary.lineage-failure"
DUPLICATE_DELIVERY = "boundary.duplicate-delivery"


def create_boundary_watch(
    output: Path,
    *,
    plan_id: str,
    monitor_id: str,
    monitor_artifact_sha256: Optional[str] = None,
    coverage_manifest_id: Optional[str] = None,
    coverage_manifest_sha256: Optional[str] = None,
    maximum_probe_miss_rate: float = 0.01,
    maximum_benign_false_alarm_rate: float = 0.01,
    maximum_lineage_failure_rate: float = 0.01,
    maximum_duplicate_delivery_rate: float = 0.01,
    family_alpha: float = 0.05,
    signer_public_key_pem: Optional[bytes] = None,
    created_at: Optional[str] = None,
) -> Dict[str, Any]:
    """Preregister a fixed four-monitor family before scheduled probes begin."""

    monitors = [
        MonitorSpec(
            PROBE_MISS,
            "false_negative_rate",
            maximum_probe_miss_rate,
            "boundary_signal",
            "probe_miss",
        ),
        MonitorSpec(
            BENIGN_FALSE_ALARM,
            "false_positive_rate",
            maximum_benign_false_alarm_rate,
            "boundary_signal",
            "benign_false_alarm",
        ),
        MonitorSpec(
            LINEAGE_FAILURE,
            "false_negative_rate",
            maximum_lineage_failure_rate,
            "boundary_signal",
            "lineage_failure",
        ),
        MonitorSpec(
            DUPLICATE_DELIVERY,
            "false_positive_rate",
            maximum_duplicate_delivery_rate,
            "boundary_signal",
            "duplicate_delivery",
        ),
    ]
    return create_monitor_bundle(
        output,
        plan_id=plan_id,
        detector=monitor_id,
        threshold=0.5,
        monitors=monitors,
        family_alpha=family_alpha,
        sampling="complete_population",
        labeling_protocol="scheduled-synthetic-canaries-v1",
        detector_artifact_sha256=monitor_artifact_sha256,
        policy_id=coverage_manifest_id,
        policy_sha256=coverage_manifest_sha256,
        signer_public_key_pem=signer_public_key_pem,
        created_at=created_at,
    )


def append_boundary_watch_batch(
    bundle: Path,
    *,
    batch_id: str,
    coverage_report: Path,
    boundary_evaluation: Path,
    observed_at: Optional[str] = None,
    signing_key_pem: Optional[bytes] = None,
    generated_at: Optional[str] = None,
) -> Dict[str, Any]:
    """Append aggregate counts from one disjoint, completed synthetic probe batch."""

    coverage, coverage_raw = _load_evidence("coverage", Path(coverage_report))
    boundary, boundary_raw = load_boundary_evaluation(Path(boundary_evaluation))
    plan, _ = _load_plan(Path(bundle))
    control = plan["control"]
    if boundary["monitor"]["monitor_id"] != control["detector"]:
        raise ValueError("boundary evaluation monitor does not match the BoundaryWatch plan")
    if (
        control["detector_artifact_sha256"] is not None
        and boundary["monitor"]["artifact_sha256"] != control["detector_artifact_sha256"]
    ):
        raise ValueError("boundary evaluation artifact does not match the BoundaryWatch plan")
    if control["policy_id"] is not None and (
        coverage["manifest"]["manifest_id"] != control["policy_id"]
        or coverage["manifest"]["manifest_sha256"] != control["policy_sha256"]
    ):
        raise ValueError("coverage manifest does not match the BoundaryWatch plan")
    coverage_summary = coverage["summary"]
    boundary_summary = boundary["summary"]
    delivered = coverage_summary["delivered_probes"]
    benign = boundary_summary["benign_trajectories"]
    commitment = hashlib.sha256(
        b"lureboundary-watch-v1\x00"
        + hashlib.sha256(coverage_raw).digest()
        + hashlib.sha256(boundary_raw).digest()
    ).hexdigest()
    counts = [
        MonitorCount(
            PROBE_MISS,
            coverage_summary["missing_probes"],
            coverage_summary["total_probes"],
        ),
        MonitorCount(
            BENIGN_FALSE_ALARM,
            boundary_summary["false_positive"],
            benign,
        ),
        MonitorCount(
            LINEAGE_FAILURE,
            delivered - coverage_summary["lineage_contiguous_probes"],
            delivered,
        ),
        MonitorCount(
            DUPLICATE_DELIVERY,
            coverage_summary["duplicate_probes"],
            coverage_summary["total_probes"],
        ),
    ]
    return append_monitor_batch(
        bundle,
        batch_id=batch_id,
        counts=counts,
        observed_at=observed_at or coverage["generated_at"],
        source_commitment_sha256=commitment,
        signing_key_pem=signing_key_pem,
        generated_at=generated_at,
    )
