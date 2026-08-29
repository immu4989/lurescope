"""LureWatch: anytime-valid, privacy-minimized deployment risk monitoring.

The monitor consumes only pre-adjudicated aggregate error counts.  For each
predeclared risk limit it maintains a finite mixture of Bernoulli likelihood
ratios.  Under the null that the conditional error probability never exceeds
the declared limit, every component is a nonnegative supermartingale; their
mixture is therefore an e-process.  Ville's inequality makes the alarm valid at
every submitted batch boundary, even when operators inspect after every batch.

This is a narrow statistical and integrity control.  Representative sampling,
label quality, trust in a signing key, incident response, and authorization
decisions remain external responsibilities.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import math
import os
import re
import secrets
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from . import __version__

PLAN_SCHEMA = "https://github.com/immu4989/lurescope/spec/lurewatch-plan/v1"
ENTRY_SCHEMA = "https://github.com/immu4989/lurescope/spec/lurewatch-entry/v1"
CHECKPOINT_PREDICATE_TYPE = (
    "https://github.com/immu4989/lurescope/spec/lurewatch-checkpoint/v1"
)
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
DSSE_PAYLOAD_TYPE = "application/vnd.in-toto+json"

PLAN_FILE = "monitor-plan.json"
ENTRIES_DIRECTORY = "entries"
CHECKPOINTS_DIRECTORY = "checkpoints"
LOCK_FILE = ".append.lock"

METHOD = "predeclared_mixture_bernoulli_e_process_v1"
MULTIPLE_MONITOR_CONTROL = "bonferroni_fixed_family_v1"
ALTERNATIVE_GRID_FRACTIONS = tuple(2.0**-index for index in range(1, 13))
MAX_MONITORS = 64
MAX_ENTRIES = 100_000
MAX_ARTIFACT_BYTES = 2 * 1024 * 1024
MAX_CUMULATIVE_TRIALS = 10**12
MIN_DECLARED_PROBABILITY = 1e-9

_SHA256 = re.compile(r"^[a-f0-9]{64}$")
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@+/-]{0,199}$")
_METRICS = {"false_positive_rate", "false_negative_rate"}
_SAMPLING = {
    "complete_population",
    "consecutive_sample",
    "random_sample",
    "operator_declared_other",
}
_PRIVACY = {
    "aggregate_only": True,
    "contains_message_content": False,
    "contains_case_identifiers": False,
    "contains_addresses": False,
    "contains_per_message_scores": False,
    "contains_per_message_labels": False,
}
_FRAMEWORK_MAPPINGS = {
    "nist_ai_rmf": ["MEASURE-2.4", "MANAGE-4.1"],
    "nist_sp_800_53": ["CA-7"],
    "relationship": "evidence_relevant_not_compliance_determination",
}
_LIMITATIONS = [
    "representative_conditionally_independent_adjudicated_sample_required",
    "label_quality_and_sampling_protocol_not_verified",
    "missing_or_delayed_labels_must_not_be_counted_as_correct_outcomes",
    "model_policy_threshold_and_population_changes_require_a_new_plan",
    "alarm_evidence_applies_only_at_submitted_batch_boundaries",
    "no_alarm_is_not_proof_that_risk_is_below_the_limit",
    "bonferroni_control_applies_only_to_the_fixed_declared_monitor_family",
    "hash_chaining_does_not_prevent_tail_deletion_without_external_checkpointing",
    "unsigned_checkpoints_do_not_authenticate_an_issuer",
    "framework_mappings_are_not_compliance_or_authorization_determinations",
]
_INTERPRETATION_BOUNDARY = (
    "A breach is anytime-valid statistical evidence that a predeclared aggregate error-rate "
    "limit was exceeded under the plan assumptions. No breach is not proof of safety, and "
    "this package is not certification, compliance, or authorization evidence by itself."
)


@dataclass(frozen=True)
class MonitorSpec:
    """One predeclared Bernoulli error-rate monitor."""

    monitor_id: str
    metric: str
    risk_limit: float
    slice_dimension: str = "overall"
    slice_value: str = "overall"


@dataclass(frozen=True)
class MonitorCount:
    """Aggregate events and eligible trials for one submitted batch."""

    monitor_id: str
    events: int
    trials: int


def _timestamp() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def _parse_timestamp(value: Any, field: str) -> datetime:
    if not isinstance(value, str):
        raise ValueError(f"{field} must be an ISO 8601 timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{field} must be an ISO 8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"{field} must include a UTC offset")
    return parsed


def canonical_json(value: Mapping[str, Any]) -> bytes:
    """Return stable UTF-8 JSON bytes used by all LureWatch digests."""

    return (
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _strict_json(payload: bytes, label: str) -> Any:
    def no_duplicates(pairs: Sequence[Tuple[str, Any]]) -> Dict[str, Any]:
        result: Dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"{label} contains duplicate key {key!r}")
            result[key] = value
        return result

    def no_constants(value: str) -> None:
        raise ValueError(f"{label} contains non-standard JSON constant {value}")

    try:
        return json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=no_duplicates,
            parse_constant=no_constants,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{label} is not strict UTF-8 JSON") from exc


def _read_regular(path: Path, maximum: int = MAX_ARTIFACT_BYTES) -> bytes:
    path = Path(path)
    if path.is_symlink():
        raise ValueError(f"refusing symbolic-link artifact: {path}")
    if not path.is_file():
        raise FileNotFoundError(path)
    if path.stat().st_size > maximum:
        raise ValueError(f"{path.name} exceeds the {maximum} byte safety limit")
    if os.name == "posix" and path.stat().st_mode & 0o077:
        raise ValueError(f"{path.name} must not grant group or world access")
    return path.read_bytes()


def _write_new(path: Path, payload: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
    except Exception:
        path.unlink(missing_ok=True)
        raise


def _safe_id(value: Any, field: str) -> str:
    if not isinstance(value, str) or _SAFE_ID.fullmatch(value) is None:
        raise ValueError(f"{field} must be a portable 1-200 character identifier")
    return value


def _probability(value: Any, field: str, *, open_interval: bool = False) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{field} must be a probability")
    result = float(value)
    valid = 0 < result < 1 if open_interval else 0 <= result <= 1
    if not math.isfinite(result) or not valid:
        interval = "(0, 1)" if open_interval else "[0, 1]"
        raise ValueError(f"{field} must be finite and in {interval}")
    return result


def _integer(value: Any, field: str, *, maximum: int = MAX_CUMULATIVE_TRIALS) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= maximum:
        raise ValueError(f"{field} must be an integer between 0 and {maximum}")
    return value


def _digest(value: Any, field: str, *, nullable: bool = False) -> Optional[str]:
    if value is None and nullable:
        return None
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise ValueError(f"{field} must be a lowercase SHA-256 digest")
    return value


def public_key_id(public_key_pem: bytes) -> str:
    """Return the SHA-256 identity of an ECDSA P-256 public key."""

    try:
        key = serialization.load_pem_public_key(public_key_pem)
    except (TypeError, ValueError) as exc:
        raise ValueError("could not load a PEM public key") from exc
    if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(
        key.curve, ec.SECP256R1
    ):
        raise ValueError("LureWatch requires an ECDSA P-256 public key")
    der = key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return _sha256(der)


def _private_key(private_key_pem: bytes) -> ec.EllipticCurvePrivateKey:
    try:
        key = serialization.load_pem_private_key(private_key_pem, password=None)
    except (TypeError, ValueError) as exc:
        raise ValueError("could not load an unencrypted PEM private key") from exc
    if not isinstance(key, ec.EllipticCurvePrivateKey) or not isinstance(
        key.curve, ec.SECP256R1
    ):
        raise ValueError("LureWatch requires an unencrypted ECDSA P-256 private key")
    return key


def _private_key_id(key: ec.EllipticCurvePrivateKey) -> str:
    der = key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return _sha256(der)


def _pae(payload: bytes) -> bytes:
    payload_type = DSSE_PAYLOAD_TYPE.encode("utf-8")
    return (
        b"DSSEv1 "
        + str(len(payload_type)).encode("ascii")
        + b" "
        + payload_type
        + b" "
        + str(len(payload)).encode("ascii")
        + b" "
        + payload
    )


def _sign_statement(statement_raw: bytes, key: ec.EllipticCurvePrivateKey) -> Dict[str, Any]:
    signature = key.sign(_pae(statement_raw), ec.ECDSA(hashes.SHA256()))
    return {
        "payloadType": DSSE_PAYLOAD_TYPE,
        "payload": base64.b64encode(statement_raw).decode("ascii"),
        "signatures": [
            {
                "keyid": _private_key_id(key),
                "sig": base64.b64encode(signature).decode("ascii"),
            }
        ],
    }


def _verify_envelope(
    envelope: Mapping[str, Any], statement_raw: bytes, public_key_pem: bytes
) -> str:
    if set(envelope) != {"payloadType", "payload", "signatures"}:
        raise ValueError("DSSE envelope has unsupported fields")
    if envelope.get("payloadType") != DSSE_PAYLOAD_TYPE:
        raise ValueError("DSSE envelope has an unsupported payload type")
    signatures = envelope.get("signatures")
    if not isinstance(signatures, list) or len(signatures) != 1:
        raise ValueError("LureWatch DSSE requires exactly one signature")
    item = signatures[0]
    if not isinstance(item, dict) or set(item) != {"keyid", "sig"}:
        raise ValueError("LureWatch DSSE signature shape is invalid")
    key_id = _digest(item.get("keyid"), "DSSE signature keyid")
    try:
        embedded = base64.b64decode(envelope.get("payload", ""), validate=True)
        signature = base64.b64decode(item.get("sig", ""), validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ValueError("DSSE payload or signature is not valid base64") from exc
    if not secrets.compare_digest(embedded, statement_raw):
        raise ValueError("DSSE payload does not match the checkpoint statement")
    try:
        key = serialization.load_pem_public_key(public_key_pem)
    except (TypeError, ValueError) as exc:
        raise ValueError("could not load a PEM public key") from exc
    if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(
        key.curve, ec.SECP256R1
    ):
        raise ValueError("LureWatch requires an ECDSA P-256 public key")
    if not secrets.compare_digest(str(key_id), public_key_id(public_key_pem)):
        raise ValueError("DSSE keyid does not match the supplied public key")
    try:
        key.verify(signature, _pae(statement_raw), ec.ECDSA(hashes.SHA256()))
    except InvalidSignature as exc:
        raise ValueError("LureWatch DSSE signature is invalid") from exc
    return str(key_id)


def mixture_log_e_value(events: int, trials: int, risk_limit: float) -> float:
    """Return the log e-value for a predeclared Bernoulli upper-risk null.

    Each alternative is ``risk_limit + (1-risk_limit) * fraction`` for the
    fixed fractions in :data:`ALTERNATIVE_GRID_FRACTIONS`.  A finite uniform
    mixture avoids post-hoc alternative selection while retaining power over a
    broad range of deterioration magnitudes.
    """

    events = _integer(events, "events")
    trials = _integer(trials, "trials")
    if events > trials:
        raise ValueError("events cannot exceed trials")
    limit = _probability(risk_limit, "risk_limit", open_interval=True)
    if not MIN_DECLARED_PROBABILITY <= limit <= 1.0 - MIN_DECLARED_PROBABILITY:
        raise ValueError(
            f"risk_limit must be between {MIN_DECLARED_PROBABILITY:g} and "
            f"{1.0 - MIN_DECLARED_PROBABILITY:g}"
        )
    if trials == 0:
        return 0.0
    components = []
    for fraction in ALTERNATIVE_GRID_FRACTIONS:
        alternative = limit + (1.0 - limit) * fraction
        components.append(
            events * math.log(alternative / limit)
            + (trials - events) * math.log((1.0 - alternative) / (1.0 - limit))
        )
    maximum = max(components)
    return maximum + math.log(
        math.fsum(math.exp(value - maximum) for value in components)
    ) - math.log(len(components))


def _validate_monitor(raw: Any, field: str) -> Dict[str, Any]:
    required = {
        "monitor_id",
        "metric",
        "risk_limit",
        "slice_dimension",
        "slice_value",
        "event_definition",
        "denominator_definition",
    }
    if not isinstance(raw, dict) or set(raw) != required:
        raise ValueError(f"{field} violates the LureWatch monitor allowlist")
    monitor_id = _safe_id(raw["monitor_id"], f"{field}.monitor_id")
    metric = raw["metric"]
    if metric not in _METRICS:
        raise ValueError(f"{field}.metric is unsupported")
    limit = _probability(raw["risk_limit"], f"{field}.risk_limit", open_interval=True)
    if not MIN_DECLARED_PROBABILITY <= limit <= 1.0 - MIN_DECLARED_PROBABILITY:
        raise ValueError(f"{field}.risk_limit is outside the supported numerical range")
    _safe_id(raw["slice_dimension"], f"{field}.slice_dimension")
    _safe_id(raw["slice_value"], f"{field}.slice_value")
    expected = {
        "false_positive_rate": ("false_positive", "actual_benign"),
        "false_negative_rate": ("false_negative", "actual_fraud"),
    }[metric]
    if (raw["event_definition"], raw["denominator_definition"]) != expected:
        raise ValueError(f"{field} event and denominator do not match its metric")
    return {**raw, "monitor_id": monitor_id}


def _monitor_payload(spec: MonitorSpec) -> Dict[str, Any]:
    if spec.metric not in _METRICS:
        raise ValueError(f"unsupported monitor metric: {spec.metric}")
    event, denominator = {
        "false_positive_rate": ("false_positive", "actual_benign"),
        "false_negative_rate": ("false_negative", "actual_fraud"),
    }[spec.metric]
    payload = {
        "monitor_id": spec.monitor_id,
        "metric": spec.metric,
        "risk_limit": spec.risk_limit,
        "slice_dimension": spec.slice_dimension,
        "slice_value": spec.slice_value,
        "event_definition": event,
        "denominator_definition": denominator,
    }
    return _validate_monitor(payload, f"monitor[{spec.monitor_id}]")


def validate_monitor_plan(plan: Mapping[str, Any]) -> Dict[str, Any]:
    required = {
        "schema",
        "schema_version",
        "plan_id",
        "created_at",
        "producer",
        "control",
        "protocol",
        "monitors",
        "authentication",
        "privacy",
        "framework_mappings",
        "limitations",
        "interpretation_boundary",
    }
    if not isinstance(plan, dict) or set(plan) != required:
        raise ValueError("monitor plan violates the LureWatch v1 allowlist")
    if plan["schema"] != PLAN_SCHEMA or plan["schema_version"] != "1.0":
        raise ValueError("unsupported LureWatch plan version")
    _safe_id(plan["plan_id"], "plan_id")
    _parse_timestamp(plan["created_at"], "created_at")
    producer = plan["producer"]
    if not isinstance(producer, dict) or set(producer) != {"name", "version"}:
        raise ValueError("plan producer is invalid")
    if producer["name"] != "lurescope":
        raise ValueError("plan producer must be lurescope")
    _safe_id(producer["version"], "producer.version")
    control = plan["control"]
    if not isinstance(control, dict) or set(control) != {
        "detector",
        "detector_artifact_sha256",
        "threshold",
        "policy_id",
        "policy_sha256",
    }:
        raise ValueError("plan control binding is invalid")
    _safe_id(control["detector"], "control.detector")
    _digest(control["detector_artifact_sha256"], "control.detector_artifact_sha256", nullable=True)
    _probability(control["threshold"], "control.threshold")
    if control["policy_id"] is not None:
        _safe_id(control["policy_id"], "control.policy_id")
    _digest(control["policy_sha256"], "control.policy_sha256", nullable=True)
    if (control["policy_id"] is None) != (control["policy_sha256"] is None):
        raise ValueError("policy_id and policy_sha256 must either both be set or both be null")
    protocol = plan["protocol"]
    if not isinstance(protocol, dict) or set(protocol) != {
        "method",
        "family_alpha",
        "multiple_monitor_control",
        "look_unit",
        "sampling",
        "labeling_protocol",
        "alternative_grid_fractions",
    }:
        raise ValueError("plan protocol is invalid")
    if protocol["method"] != METHOD:
        raise ValueError("unsupported LureWatch statistical method")
    alpha = _probability(protocol["family_alpha"], "protocol.family_alpha", open_interval=True)
    if not MIN_DECLARED_PROBABILITY <= alpha <= 0.2:
        raise ValueError(
            f"family_alpha must be between {MIN_DECLARED_PROBABILITY:g} and 0.2"
        )
    if protocol["multiple_monitor_control"] != MULTIPLE_MONITOR_CONTROL:
        raise ValueError("unsupported multiple-monitor control")
    if protocol["look_unit"] != "submitted_adjudicated_batch":
        raise ValueError("unsupported LureWatch look unit")
    if protocol["sampling"] not in _SAMPLING:
        raise ValueError("unsupported sampling protocol")
    _safe_id(protocol["labeling_protocol"], "protocol.labeling_protocol")
    if protocol["alternative_grid_fractions"] != list(ALTERNATIVE_GRID_FRACTIONS):
        raise ValueError("alternative grid is not the LureWatch v1 predeclared grid")
    monitors = plan["monitors"]
    if not isinstance(monitors, list) or not 1 <= len(monitors) <= MAX_MONITORS:
        raise ValueError(f"plan must contain between 1 and {MAX_MONITORS} monitors")
    parsed = [_validate_monitor(item, f"monitors[{index}]") for index, item in enumerate(monitors)]
    ids = [item["monitor_id"] for item in parsed]
    if ids != sorted(ids) or len(ids) != len(set(ids)):
        raise ValueError("monitor IDs must be unique and sorted")
    populations = [
        (item["metric"], item["slice_dimension"], item["slice_value"])
        for item in parsed
    ]
    if len(populations) != len(set(populations)):
        raise ValueError("each metric and slice population may be monitored only once")
    authentication = plan["authentication"]
    if not isinstance(authentication, dict) or set(authentication) != {
        "mode",
        "signer_key_id",
    }:
        raise ValueError("plan authentication is invalid")
    if authentication["mode"] not in {"unsigned", "ecdsa-p256-dsse"}:
        raise ValueError("unsupported authentication mode")
    signer = authentication["signer_key_id"]
    if authentication["mode"] == "unsigned":
        if signer is not None:
            raise ValueError("unsigned plans cannot declare a signer key")
    else:
        _digest(signer, "authentication.signer_key_id")
    if plan["privacy"] != _PRIVACY:
        raise ValueError("plan privacy boundary is invalid")
    if plan["framework_mappings"] != _FRAMEWORK_MAPPINGS:
        raise ValueError("plan framework mappings are invalid")
    if plan["limitations"] != _LIMITATIONS:
        raise ValueError("plan limitations are invalid")
    if plan["interpretation_boundary"] != _INTERPRETATION_BOUNDARY:
        raise ValueError("plan interpretation boundary is invalid")
    return dict(plan)


def _load_plan(bundle: Path) -> Tuple[Dict[str, Any], bytes]:
    raw = _read_regular(bundle / PLAN_FILE)
    plan = _strict_json(raw, PLAN_FILE)
    validate_monitor_plan(plan)
    if raw != canonical_json(plan):
        raise ValueError("monitor plan must use canonical JSON encoding")
    return plan, raw


def create_monitor_bundle(
    output: Path,
    *,
    plan_id: str,
    detector: str,
    threshold: float,
    monitors: Sequence[MonitorSpec],
    family_alpha: float = 0.05,
    sampling: str = "random_sample",
    labeling_protocol: str = "human-adjudication-v1",
    detector_artifact_sha256: Optional[str] = None,
    policy_id: Optional[str] = None,
    policy_sha256: Optional[str] = None,
    signer_public_key_pem: Optional[bytes] = None,
    created_at: Optional[str] = None,
) -> Dict[str, Any]:
    """Create a private immutable LureWatch plan and empty checkpoint chain."""

    target = Path(output)
    if target.exists() or target.is_symlink():
        raise FileExistsError(target)
    _safe_id(plan_id, "plan_id")
    _safe_id(detector, "detector")
    monitor_payloads = sorted(
        (_monitor_payload(item) for item in monitors), key=lambda item: item["monitor_id"]
    )
    authentication = (
        {"mode": "unsigned", "signer_key_id": None}
        if signer_public_key_pem is None
        else {
            "mode": "ecdsa-p256-dsse",
            "signer_key_id": public_key_id(signer_public_key_pem),
        }
    )
    plan = {
        "schema": PLAN_SCHEMA,
        "schema_version": "1.0",
        "plan_id": plan_id,
        "created_at": created_at or _timestamp(),
        "producer": {"name": "lurescope", "version": __version__},
        "control": {
            "detector": detector,
            "detector_artifact_sha256": detector_artifact_sha256,
            "threshold": threshold,
            "policy_id": policy_id,
            "policy_sha256": policy_sha256,
        },
        "protocol": {
            "method": METHOD,
            "family_alpha": family_alpha,
            "multiple_monitor_control": MULTIPLE_MONITOR_CONTROL,
            "look_unit": "submitted_adjudicated_batch",
            "sampling": sampling,
            "labeling_protocol": labeling_protocol,
            "alternative_grid_fractions": list(ALTERNATIVE_GRID_FRACTIONS),
        },
        "monitors": monitor_payloads,
        "authentication": authentication,
        "privacy": dict(_PRIVACY),
        "framework_mappings": dict(_FRAMEWORK_MAPPINGS),
        "limitations": list(_LIMITATIONS),
        "interpretation_boundary": _INTERPRETATION_BOUNDARY,
    }
    validate_monitor_plan(plan)
    target.mkdir(mode=0o700)
    try:
        (target / ENTRIES_DIRECTORY).mkdir(mode=0o700)
        (target / CHECKPOINTS_DIRECTORY).mkdir(mode=0o700)
        _write_new(target / PLAN_FILE, canonical_json(plan))
    except Exception:
        for directory in (target / CHECKPOINTS_DIRECTORY, target / ENTRIES_DIRECTORY):
            if directory.is_dir():
                directory.rmdir()
        target.rmdir()
        raise
    return plan


def _entry_name(sequence: int) -> str:
    return f"{sequence:08d}.json"


def _statement_name(sequence: int) -> str:
    return f"{sequence:08d}.statement.json"


def _dsse_name(sequence: int) -> str:
    return f"{sequence:08d}.dsse.json"


def _listed_sequences(
    directory: Path,
    suffix: str,
    *,
    allowed_suffixes: Optional[Sequence[str]] = None,
) -> List[int]:
    allowed = tuple(allowed_suffixes or (suffix,))
    result = []
    for path in directory.iterdir():
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"unexpected non-regular checkpoint artifact: {path.name}")
        matched = next((item for item in allowed if path.name.endswith(item)), None)
        if matched is None:
            raise ValueError(f"unexpected checkpoint artifact: {path.name}")
        if matched != suffix:
            continue
        prefix = path.name[: -len(suffix)]
        if len(prefix) != 8 or not prefix.isdigit():
            raise ValueError(f"invalid checkpoint sequence filename: {path.name}")
        result.append(int(prefix))
    result.sort()
    if result != list(range(1, len(result) + 1)):
        raise ValueError("checkpoint sequence has a gap, duplicate, or non-one origin")
    if len(result) > MAX_ENTRIES:
        raise ValueError("monitor bundle exceeds the entry safety limit")
    return result


def _validate_count(raw: Any, field: str) -> Dict[str, int | str]:
    if not isinstance(raw, dict) or set(raw) != {"monitor_id", "events", "trials"}:
        raise ValueError(f"{field} violates the monitor-count allowlist")
    monitor_id = _safe_id(raw["monitor_id"], f"{field}.monitor_id")
    events = _integer(raw["events"], f"{field}.events")
    trials = _integer(raw["trials"], f"{field}.trials")
    if events > trials:
        raise ValueError(f"{field}.events cannot exceed trials")
    return {"monitor_id": monitor_id, "events": events, "trials": trials}


def _state_for(
    monitor: Mapping[str, Any],
    events: int,
    trials: int,
    previous_max_log_e: float,
    per_monitor_alpha: float,
) -> Dict[str, Any]:
    current = mixture_log_e_value(events, trials, monitor["risk_limit"])
    maximum = max(0.0, previous_max_log_e, current)
    threshold = -math.log(per_monitor_alpha)
    return {
        "monitor_id": monitor["monitor_id"],
        "cumulative_events": events,
        "cumulative_trials": trials,
        "empirical_rate": None if trials == 0 else events / trials,
        "log_e_value": current,
        "max_log_e_value": maximum,
        "alarm_log_threshold": threshold,
        "per_monitor_alpha": per_monitor_alpha,
        "status": "breach" if maximum >= threshold else "monitoring",
    }


def _validate_state(
    raw: Any,
    monitor: Mapping[str, Any],
    previous: Optional[Mapping[str, Any]],
    batch_count: Mapping[str, Any],
    per_monitor_alpha: float,
    field: str,
) -> Dict[str, Any]:
    required = {
        "monitor_id",
        "cumulative_events",
        "cumulative_trials",
        "empirical_rate",
        "log_e_value",
        "max_log_e_value",
        "alarm_log_threshold",
        "per_monitor_alpha",
        "status",
    }
    if not isinstance(raw, dict) or set(raw) != required:
        raise ValueError(f"{field} violates the monitor-state allowlist")
    old_events = 0 if previous is None else previous["cumulative_events"]
    old_trials = 0 if previous is None else previous["cumulative_trials"]
    old_max = 0.0 if previous is None else previous["max_log_e_value"]
    expected = _state_for(
        monitor,
        old_events + batch_count["events"],
        old_trials + batch_count["trials"],
        old_max,
        per_monitor_alpha,
    )
    if raw != expected:
        raise ValueError(f"{field} does not recompute from the plan and aggregate counts")
    return dict(raw)


def _validate_entry(
    entry: Any,
    plan: Mapping[str, Any],
    plan_sha256: str,
    previous_entry: Optional[Mapping[str, Any]],
    previous_entry_sha256: Optional[str],
) -> Dict[str, Any]:
    required = {
        "schema",
        "schema_version",
        "sequence",
        "generated_at",
        "plan_id",
        "plan_sha256",
        "previous_entry_sha256",
        "batch",
        "states",
        "family_status",
        "privacy",
        "interpretation_boundary",
    }
    if not isinstance(entry, dict) or set(entry) != required:
        raise ValueError("monitor entry violates the LureWatch v1 allowlist")
    if entry["schema"] != ENTRY_SCHEMA or entry["schema_version"] != "1.0":
        raise ValueError("unsupported LureWatch entry version")
    sequence = _integer(entry["sequence"], "entry.sequence", maximum=MAX_ENTRIES)
    expected_sequence = 1 if previous_entry is None else previous_entry["sequence"] + 1
    if sequence != expected_sequence:
        raise ValueError("monitor entry sequence is not contiguous")
    generated_at = _parse_timestamp(entry["generated_at"], "entry.generated_at")
    if previous_entry is not None:
        previous_generated = _parse_timestamp(
            previous_entry["generated_at"], "previous_entry.generated_at"
        )
        if generated_at < previous_generated:
            raise ValueError("monitor entry generated_at cannot move backward")
    if entry["plan_id"] != plan["plan_id"] or entry["plan_sha256"] != plan_sha256:
        raise ValueError("monitor entry is not bound to this plan")
    if entry["previous_entry_sha256"] != previous_entry_sha256:
        raise ValueError("monitor entry predecessor binding is invalid")
    batch = entry["batch"]
    if not isinstance(batch, dict) or set(batch) != {
        "batch_id",
        "observed_at",
        "source_commitment_sha256",
        "counts",
    }:
        raise ValueError("monitor batch violates the v1 allowlist")
    _safe_id(batch["batch_id"], "batch.batch_id")
    _parse_timestamp(batch["observed_at"], "batch.observed_at")
    _digest(batch["source_commitment_sha256"], "batch.source_commitment_sha256", nullable=True)
    counts = batch["counts"]
    if not isinstance(counts, list) or len(counts) != len(plan["monitors"]):
        raise ValueError("batch must provide one count for every predeclared monitor")
    parsed_counts = [
        _validate_count(item, f"batch.counts[{index}]")
        for index, item in enumerate(counts)
    ]
    monitor_ids = [item["monitor_id"] for item in plan["monitors"]]
    if [item["monitor_id"] for item in parsed_counts] != monitor_ids:
        raise ValueError("batch counts must follow the plan monitor order")
    if previous_entry is not None and batch["batch_id"] in {
        previous_entry["batch"]["batch_id"]
    }:
        raise ValueError("consecutive monitor batches cannot reuse a batch_id")
    states = entry["states"]
    if not isinstance(states, list) or len(states) != len(plan["monitors"]):
        raise ValueError("entry states must match the declared monitor family")
    previous_states = {
        item["monitor_id"]: item for item in (previous_entry or {}).get("states", [])
    }
    per_alpha = plan["protocol"]["family_alpha"] / len(plan["monitors"])
    parsed_states = [
        _validate_state(
            state,
            monitor,
            previous_states.get(monitor["monitor_id"]),
            count,
            per_alpha,
            f"states[{index}]",
        )
        for index, (state, monitor, count) in enumerate(
            zip(states, plan["monitors"], parsed_counts, strict=True)
        )
    ]
    expected_family = (
        "breach" if any(item["status"] == "breach" for item in parsed_states) else "monitoring"
    )
    if entry["family_status"] != expected_family:
        raise ValueError("family_status does not match monitor states")
    if entry["privacy"] != _PRIVACY:
        raise ValueError("entry privacy boundary is invalid")
    if entry["interpretation_boundary"] != _INTERPRETATION_BOUNDARY:
        raise ValueError("entry interpretation boundary is invalid")
    return dict(entry)


def _checkpoint_statement(
    plan: Mapping[str, Any],
    plan_sha256: str,
    entry: Mapping[str, Any],
    entry_sha256: str,
    previous_statement_sha256: Optional[str],
) -> Dict[str, Any]:
    sequence = entry["sequence"]
    return {
        "_type": STATEMENT_TYPE,
        "subject": [
            {"name": PLAN_FILE, "digest": {"sha256": plan_sha256}},
            {
                "name": f"{ENTRIES_DIRECTORY}/{_entry_name(sequence)}",
                "digest": {"sha256": entry_sha256},
            },
        ],
        "predicateType": CHECKPOINT_PREDICATE_TYPE,
        "predicate": {
            "spec": "lurewatch-checkpoint",
            "spec_version": "1.0",
            "plan_id": plan["plan_id"],
            "sequence": sequence,
            "generated_at": entry["generated_at"],
            "previous_statement_sha256": previous_statement_sha256,
            "family_status": entry["family_status"],
            "authentication_mode": plan["authentication"]["mode"],
            "framework_mappings": dict(_FRAMEWORK_MAPPINGS),
            "limitations": list(_LIMITATIONS),
            "interpretation_boundary": _INTERPRETATION_BOUNDARY,
        },
    }


def _validate_statement(
    statement: Any,
    expected: Mapping[str, Any],
) -> Dict[str, Any]:
    if not isinstance(statement, dict) or statement != expected:
        raise ValueError("checkpoint statement does not recompute from its plan and entry")
    return dict(statement)


def _bundle_shape(bundle: Path, *, allow_lock: bool = False) -> Tuple[Path, Path]:
    bundle = Path(bundle)
    if bundle.is_symlink():
        raise ValueError("refusing symbolic-link monitor bundle")
    if not bundle.is_dir():
        raise FileNotFoundError(bundle)
    allowed = {PLAN_FILE, ENTRIES_DIRECTORY, CHECKPOINTS_DIRECTORY}
    actual = {path.name for path in bundle.iterdir()}
    if LOCK_FILE in actual and not allow_lock:
        raise ValueError("monitor append is in progress or a stale append lock exists")
    if allow_lock:
        allowed.add(LOCK_FILE)
    if actual != allowed:
        raise ValueError("monitor bundle contains unexpected artifacts")
    entries = bundle / ENTRIES_DIRECTORY
    checkpoints = bundle / CHECKPOINTS_DIRECTORY
    if (
        entries.is_symlink()
        or checkpoints.is_symlink()
        or not entries.is_dir()
        or not checkpoints.is_dir()
    ):
        raise ValueError("monitor artifact directories must be regular directories")
    if os.name == "posix":
        for directory in (bundle, entries, checkpoints):
            if directory.stat().st_mode & 0o077:
                raise ValueError("monitor bundle directories must not grant group or world access")
    return entries, checkpoints


def verify_monitor_bundle(
    bundle: Path,
    *,
    public_key_pem: Optional[bytes] = None,
    _allow_lock: bool = False,
) -> Dict[str, Any]:
    """Strictly revalidate every statistic, digest, chain link, and signature."""

    entries_dir, checkpoints_dir = _bundle_shape(Path(bundle), allow_lock=_allow_lock)
    plan, plan_raw = _load_plan(Path(bundle))
    plan_sha = _sha256(plan_raw)
    entry_sequences = _listed_sequences(entries_dir, ".json")
    checkpoint_suffixes = (
        (".statement.json", ".dsse.json")
        if plan["authentication"]["mode"] == "ecdsa-p256-dsse"
        else (".statement.json",)
    )
    statement_sequences = _listed_sequences(
        checkpoints_dir,
        ".statement.json",
        allowed_suffixes=checkpoint_suffixes,
    )
    signed = plan["authentication"]["mode"] == "ecdsa-p256-dsse"
    dsse_sequences = (
        _listed_sequences(
            checkpoints_dir,
            ".dsse.json",
            allowed_suffixes=checkpoint_suffixes,
        )
        if signed
        else []
    )
    if entry_sequences != statement_sequences or (signed and entry_sequences != dsse_sequences):
        raise ValueError("entry, statement, and signature checkpoint sequences differ")
    if not signed and any(path.name.endswith(".dsse.json") for path in checkpoints_dir.iterdir()):
        raise ValueError("unsigned monitor plan cannot contain DSSE checkpoints")
    if signed:
        if public_key_pem is None:
            raise ValueError("signed monitor verification requires the external public key")
        expected_key_id = plan["authentication"]["signer_key_id"]
        if not secrets.compare_digest(str(expected_key_id), public_key_id(public_key_pem)):
            raise ValueError("supplied public key is not the signer declared by the plan")
    previous_entry = None
    previous_entry_sha = None
    previous_statement_sha = None
    key_ids: set[str] = set()
    seen_batch_ids: set[str] = set()
    seen_source_commitments: set[str] = set()
    latest_states: List[Dict[str, Any]] = []
    family_status = "monitoring"
    for sequence in entry_sequences:
        entry_path = entries_dir / _entry_name(sequence)
        entry_raw = _read_regular(entry_path)
        entry = _strict_json(entry_raw, entry_path.name)
        _validate_entry(entry, plan, plan_sha, previous_entry, previous_entry_sha)
        if entry_raw != canonical_json(entry):
            raise ValueError(f"{entry_path.name} must use canonical JSON encoding")
        batch_id = entry["batch"]["batch_id"]
        if batch_id in seen_batch_ids:
            raise ValueError(f"batch_id {batch_id!r} appears more than once")
        seen_batch_ids.add(batch_id)
        source_commitment = entry["batch"]["source_commitment_sha256"]
        if source_commitment is not None:
            if source_commitment in seen_source_commitments:
                raise ValueError("source commitment appears in more than one monitor batch")
            seen_source_commitments.add(source_commitment)
        entry_sha = _sha256(entry_raw)
        expected_statement = _checkpoint_statement(
            plan, plan_sha, entry, entry_sha, previous_statement_sha
        )
        statement_path = checkpoints_dir / _statement_name(sequence)
        statement_raw = _read_regular(statement_path)
        statement = _strict_json(statement_raw, statement_path.name)
        _validate_statement(statement, expected_statement)
        if statement_raw != canonical_json(statement):
            raise ValueError(f"{statement_path.name} must use canonical JSON encoding")
        if signed:
            envelope_path = checkpoints_dir / _dsse_name(sequence)
            envelope_raw = _read_regular(envelope_path)
            envelope = _strict_json(envelope_raw, envelope_path.name)
            if envelope_raw != canonical_json(envelope):
                raise ValueError(f"{envelope_path.name} must use canonical JSON encoding")
            key_ids.add(_verify_envelope(envelope, statement_raw, public_key_pem or b""))
        previous_entry = entry
        previous_entry_sha = entry_sha
        previous_statement_sha = _sha256(statement_raw)
        latest_states = entry["states"]
        family_status = entry["family_status"]
    return {
        "valid": True,
        "plan_id": plan["plan_id"],
        "plan_sha256": plan_sha,
        "entry_count": len(entry_sequences),
        "latest_sequence": entry_sequences[-1] if entry_sequences else 0,
        "latest_statement_sha256": previous_statement_sha,
        "family_status": family_status,
        "states": latest_states,
        "authenticated": signed and bool(entry_sequences),
        "key_ids": sorted(key_ids),
        "interpretation_boundary": _INTERPRETATION_BOUNDARY,
    }


def _acquire_lock(bundle: Path) -> int:
    try:
        return os.open(bundle / LOCK_FILE, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError as exc:
        raise RuntimeError("another append is in progress or a stale append lock exists") from exc


def append_monitor_batch(
    bundle: Path,
    *,
    batch_id: str,
    counts: Sequence[MonitorCount],
    observed_at: Optional[str] = None,
    source_commitment_sha256: Optional[str] = None,
    signing_key_pem: Optional[bytes] = None,
    generated_at: Optional[str] = None,
) -> Dict[str, Any]:
    """Append one aggregate batch and return its recomputed checkpoint entry."""

    bundle = Path(bundle)
    _bundle_shape(bundle)
    lock = _acquire_lock(bundle)
    try:
        plan, plan_raw = _load_plan(bundle)
        signed = plan["authentication"]["mode"] == "ecdsa-p256-dsse"
        key = None
        public_key_pem = None
        if signed:
            if signing_key_pem is None:
                raise ValueError("this monitor plan requires a signing key for every append")
            key = _private_key(signing_key_pem)
            key_id = _private_key_id(key)
            if not secrets.compare_digest(key_id, plan["authentication"]["signer_key_id"]):
                raise ValueError("signing key does not match the monitor plan")
            public_key_pem = key.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        elif signing_key_pem is not None:
            raise ValueError("an unsigned monitor plan cannot add signed checkpoints")
        current = verify_monitor_bundle(
            bundle,
            public_key_pem=public_key_pem,
            _allow_lock=True,
        )
        sequence = current["latest_sequence"] + 1
        if sequence > MAX_ENTRIES:
            raise ValueError("monitor bundle reached the entry safety limit")
        _safe_id(batch_id, "batch_id")
        for existing_sequence in range(1, sequence):
            existing_path = bundle / ENTRIES_DIRECTORY / _entry_name(existing_sequence)
            existing = _strict_json(_read_regular(existing_path), existing_path.name)
            if existing["batch"]["batch_id"] == batch_id:
                raise ValueError(f"batch_id {batch_id!r} was already submitted")
            if (
                source_commitment_sha256 is not None
                and existing["batch"]["source_commitment_sha256"]
                == source_commitment_sha256
            ):
                raise ValueError("source commitment was already submitted")
        parsed_counts = sorted(
            (_validate_count(count.__dict__, f"count[{count.monitor_id}]") for count in counts),
            key=lambda item: str(item["monitor_id"]),
        )
        monitor_ids = [item["monitor_id"] for item in plan["monitors"]]
        if [item["monitor_id"] for item in parsed_counts] != monitor_ids:
            raise ValueError("counts must contain each predeclared monitor exactly once")
        _digest(source_commitment_sha256, "source_commitment_sha256", nullable=True)
        previous_entry = None
        previous_entry_sha = None
        previous_statement_sha = current["latest_statement_sha256"]
        if sequence > 1:
            previous_path = bundle / ENTRIES_DIRECTORY / _entry_name(sequence - 1)
            previous_raw = _read_regular(previous_path)
            previous_entry = _strict_json(previous_raw, previous_path.name)
            previous_entry_sha = _sha256(previous_raw)
        previous_states = {
            item["monitor_id"]: item for item in (previous_entry or {}).get("states", [])
        }
        per_alpha = plan["protocol"]["family_alpha"] / len(plan["monitors"])
        states = []
        for monitor, count in zip(plan["monitors"], parsed_counts, strict=True):
            prior = previous_states.get(monitor["monitor_id"])
            states.append(
                _state_for(
                    monitor,
                    (0 if prior is None else prior["cumulative_events"]) + count["events"],
                    (0 if prior is None else prior["cumulative_trials"]) + count["trials"],
                    0.0 if prior is None else prior["max_log_e_value"],
                    per_alpha,
                )
            )
        created = generated_at or _timestamp()
        entry = {
            "schema": ENTRY_SCHEMA,
            "schema_version": "1.0",
            "sequence": sequence,
            "generated_at": created,
            "plan_id": plan["plan_id"],
            "plan_sha256": _sha256(plan_raw),
            "previous_entry_sha256": previous_entry_sha,
            "batch": {
                "batch_id": batch_id,
                "observed_at": observed_at or created,
                "source_commitment_sha256": source_commitment_sha256,
                "counts": parsed_counts,
            },
            "states": states,
            "family_status": (
                "breach" if any(item["status"] == "breach" for item in states) else "monitoring"
            ),
            "privacy": dict(_PRIVACY),
            "interpretation_boundary": _INTERPRETATION_BOUNDARY,
        }
        _validate_entry(entry, plan, _sha256(plan_raw), previous_entry, previous_entry_sha)
        entry_raw = canonical_json(entry)
        statement = _checkpoint_statement(
            plan,
            _sha256(plan_raw),
            entry,
            _sha256(entry_raw),
            previous_statement_sha,
        )
        statement_raw = canonical_json(statement)
        entry_path = bundle / ENTRIES_DIRECTORY / _entry_name(sequence)
        statement_path = bundle / CHECKPOINTS_DIRECTORY / _statement_name(sequence)
        _write_new(entry_path, entry_raw)
        try:
            _write_new(statement_path, statement_raw)
            if key is not None:
                envelope = _sign_statement(statement_raw, key)
                _write_new(
                    bundle / CHECKPOINTS_DIRECTORY / _dsse_name(sequence),
                    canonical_json(envelope),
                )
        except Exception:
            (bundle / CHECKPOINTS_DIRECTORY / _dsse_name(sequence)).unlink(missing_ok=True)
            statement_path.unlink(missing_ok=True)
            entry_path.unlink(missing_ok=True)
            raise
        try:
            verified = verify_monitor_bundle(
                bundle,
                public_key_pem=public_key_pem,
                _allow_lock=True,
            )
            if verified["latest_sequence"] != sequence:
                raise AssertionError("appended checkpoint was not visible to strict verification")
        except Exception:
            (bundle / CHECKPOINTS_DIRECTORY / _dsse_name(sequence)).unlink(missing_ok=True)
            statement_path.unlink(missing_ok=True)
            entry_path.unlink(missing_ok=True)
            raise
        return entry
    finally:
        os.close(lock)
        (bundle / LOCK_FILE).unlink(missing_ok=True)


def default_monitors(
    false_positive_rate_limit: float,
    false_negative_rate_limit: float,
) -> List[MonitorSpec]:
    """Return the standard overall FPR/FNR monitor family."""

    return [
        MonitorSpec("overall-fnr", "false_negative_rate", false_negative_rate_limit),
        MonitorSpec("overall-fpr", "false_positive_rate", false_positive_rate_limit),
    ]


def confusion_counts(
    *,
    true_positive: int,
    false_positive: int,
    true_negative: int,
    false_negative: int,
) -> List[MonitorCount]:
    """Convert one aggregate confusion matrix to the default monitor family."""

    tp = _integer(true_positive, "true_positive")
    fp = _integer(false_positive, "false_positive")
    tn = _integer(true_negative, "true_negative")
    fn = _integer(false_negative, "false_negative")
    return [
        MonitorCount("overall-fnr", fn, tp + fn),
        MonitorCount("overall-fpr", fp, tn + fp),
    ]
