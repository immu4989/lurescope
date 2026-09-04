"""Independent offline authentication of LureArtifact SLSA provenance.

LureScope recompiles a LureAttest policy without importing LureBench, verifies
the exact DSSE payload bytes against externally supplied ECDSA P-256 keys, and
then checks the bounded in-toto Statement and SLSA Provenance v1 expectations.
It does not implement Sigstore certificate, transparency-log, or timestamp
verification and never opens the subject artifact bytes.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Mapping, Optional, Sequence

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from . import __version__
from .artifact import (
    IN_TOTO_STATEMENT_TYPE,
    SLSA_PREDICATE_TYPE,
    _uri,
    validate_artifact_plan,
)
from .identity import _digest
from .permit import (
    _canonical,
    _exact,
    _id,
    _read,
    _sha256,
    _strict,
    _timestamp,
    _timestamp_now,
    _write_new,
)

TRUST_POLICY_SCHEMA = "https://github.com/immu4989/lurebench/spec/lureattest-trust-policy-v1"
PLAN_SCHEMA = "https://github.com/immu4989/lurebench/spec/lureattest-plan-v1"
VERIFICATION_SCHEMA = "https://github.com/immu4989/lurescope/spec/lureattest-verification/v1"
DSSE_PAYLOAD_TYPE = "application/vnd.in-toto+json"
SIGNATURE_ALGORITHM = "ecdsa-p256-sha256"
MAX_BUILDERS = 64
MAX_ATTESTATIONS = 384
MAX_ENVELOPE_BYTES = 2 * 1024 * 1024
MAX_PAYLOAD_BYTES = 1024 * 1024
MAX_PUBLIC_KEY_BYTES = 64 * 1024
MAX_DEPENDENCIES = 512
_B64 = re.compile(r"^[A-Za-z0-9+/]*={0,2}$")
_B64URL = re.compile(r"^[A-Za-z0-9_-]*={0,2}$")

REQUIREMENTS = {
    "payload_type": DSSE_PAYLOAD_TYPE,
    "signature_algorithm": SIGNATURE_ALGORITHM,
    "signature_threshold": 1,
    "require_exactly_one_signature": True,
    "require_exactly_one_subject": True,
    "require_statement_sha256": True,
    "require_subject_sha256": True,
    "require_builder_identity": True,
    "require_build_type": True,
    "require_source_dependency": True,
    "require_external_parameters_commitment": True,
}
POLICY_LIMITATIONS = [
    "trusted_builder_levels_and_public_key_fingerprints_are_reviewed_external_policy_inputs",
    "external_parameter_commitments_hide_values_but_do_not_establish_that_they_are_safe",
    "policy_compilation_reads_no_dsse_envelope_public_key_source_tree_or_artifact_bytes",
    "sigstore_certificate_transparency_timestamp_and_identity_verification_are_out_of_scope",
]
PLAN_LIMITATIONS = [
    "plan_binds_every_lureartifact_provenance_claim_to_one_reviewed_signer_and_expectation",
    "plan_compilation_does_not_authenticate_signatures_or_certify_build_platforms",
    "source_matching_requires_one_exact_uri_and_sha256_resolved_dependency",
    "actual_artifact_bytes_ai_bom_documents_and_build_execution_are_not_inspected",
    "a_matching_plan_is_not_artifact_safety_quality_licensing_compliance_or_authorization",
]
VERIFICATION_LIMITATIONS = [
    "verification_is_an_independent_local_reimplementation_and_imports_no_lurebench_code",
    "ecdsa_p256_dsse_authentication_uses_only_externally_supplied_pinned_public_keys",
    "policy_slsa_levels_are_reviewed_trust_assertions_not_build_platform_certification",
    "sigstore_fulcio_rekor_rfc3161_kms_and_key_lifecycle_verification_are_not_performed",
    "subject_artifact_ai_bom_source_repository_and_build_execution_bytes_are_not_opened",
    "a_pass_authenticates_provenance_expectations_not_artifact_safety_or_authorization",
]
VERIFICATION_CHECKS = [
    "artifact_plan_contract_valid",
    "trust_policy_contract_valid",
    "attest_plan_independently_rederived",
    "evidence_directory_exact",
    "trusted_public_keys_pinned",
    "dsse_payloads_authenticated",
    "statement_digests_bound",
    "artifact_subjects_bound",
    "signer_builder_pairs_bound",
    "build_types_bound",
    "source_dependencies_bound",
    "external_parameters_bound",
]


def _bounded_list(
    value: Any, field: str, maximum: int, *, allow_empty: bool = False
) -> list[Any]:
    minimum = 0 if allow_empty else 1
    if not isinstance(value, list) or not minimum <= len(value) <= maximum:
        qualifier = "bounded" if allow_empty else "non-empty bounded"
        raise ValueError(f"{field} must be a {qualifier} array")
    return value


def _level(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value not in (1, 2, 3):
        raise ValueError(f"{field} must be an integer from 1 through 3")
    return value


def _trusted_builder(value: Any, field: str) -> Dict[str, Any]:
    builder = _exact(
        value,
        field,
        (
            "builder_id",
            "public_key_sha256",
            "signature_algorithm",
            "maximum_trusted_slsa_build_level",
        ),
    )
    _uri(builder["builder_id"], f"{field}.builder_id")
    _digest(builder["public_key_sha256"], f"{field}.public_key_sha256")
    if builder["signature_algorithm"] != SIGNATURE_ALGORITHM:
        raise ValueError(f"{field}.signature_algorithm is unsupported")
    _level(
        builder["maximum_trusted_slsa_build_level"],
        f"{field}.maximum_trusted_slsa_build_level",
    )
    return dict(builder)


def _trusted_builders(value: Any, field: str) -> list[Dict[str, Any]]:
    builders = [
        _trusted_builder(item, f"{field}[{index}]")
        for index, item in enumerate(_bounded_list(value, field, MAX_BUILDERS))
    ]
    ids = [item["builder_id"] for item in builders]
    if len(ids) != len(set(ids)):
        raise ValueError(f"{field} contains duplicate builder identities")
    return builders


def _expectation(value: Any, field: str) -> Dict[str, Any]:
    expectation = _exact(
        value,
        field,
        (
            "attestation_id",
            "public_key_sha256",
            "source_uri",
            "external_parameters_sha256",
            "minimum_slsa_build_level",
        ),
    )
    _id(expectation["attestation_id"], f"{field}.attestation_id")
    _digest(expectation["public_key_sha256"], f"{field}.public_key_sha256")
    _uri(expectation["source_uri"], f"{field}.source_uri")
    _digest(
        expectation["external_parameters_sha256"],
        f"{field}.external_parameters_sha256",
    )
    _level(expectation["minimum_slsa_build_level"], f"{field}.minimum_slsa_build_level")
    return dict(expectation)


def _expectations(value: Any, field: str) -> list[Dict[str, Any]]:
    expectations = [
        _expectation(item, f"{field}[{index}]")
        for index, item in enumerate(_bounded_list(value, field, MAX_ATTESTATIONS))
    ]
    ids = [item["attestation_id"] for item in expectations]
    if len(ids) != len(set(ids)):
        raise ValueError(f"{field} contains duplicate attestation identifiers")
    return expectations


def _requirements(value: Any, field: str) -> Dict[str, Any]:
    reviewed = _exact(value, field, tuple(REQUIREMENTS))
    if reviewed != REQUIREMENTS:
        raise ValueError(f"{field} does not match the LureAttest v1 fail-closed profile")
    return dict(reviewed)


def _artifact_attestations(
    artifact_plan: Mapping[str, Any],
) -> dict[str, tuple[str, Mapping[str, Any]]]:
    result: dict[str, tuple[str, Mapping[str, Any]]] = {}
    for workload in artifact_plan["workloads"]:
        for attestation in workload["attestations"]:
            attestation_id = attestation["attestation_id"]
            if attestation_id in result:
                raise ValueError("artifact plan contains ambiguous attestation identifiers")
            result[attestation_id] = (workload["workload_principal_id"], attestation)
    if not result or len(result) > MAX_ATTESTATIONS:
        raise ValueError("artifact plan contains an unsupported attestation count")
    return result


def validate_trust_policy(value: Any, artifact_plan: Mapping[str, Any]) -> Dict[str, Any]:
    reviewed_plan = validate_artifact_plan(artifact_plan)
    policy = _exact(
        value,
        "LureAttest trust policy",
        (
            "schema",
            "schema_version",
            "policy_id",
            "created_at",
            "artifact_plan_sha256",
            "trusted_builders",
            "attestation_expectations",
            "requirements",
            "limitations",
        ),
    )
    if policy["schema"] != TRUST_POLICY_SCHEMA or policy["schema_version"] != 1:
        raise ValueError("unsupported LureAttest trust-policy schema")
    _id(policy["policy_id"], "LureAttest trust policy.policy_id")
    _timestamp(policy["created_at"], "LureAttest trust policy.created_at")
    if policy["artifact_plan_sha256"] != _sha256(_canonical(reviewed_plan)):
        raise ValueError("LureAttest trust policy does not bind the artifact plan")
    if _time(policy["created_at"]) < _time(reviewed_plan["created_at"]):
        raise ValueError("LureAttest trust policy predates the artifact plan")
    builders = _trusted_builders(policy["trusted_builders"], "trusted_builders")
    expectations = _expectations(
        policy["attestation_expectations"], "attestation_expectations"
    )
    _requirements(policy["requirements"], "requirements")
    if policy["limitations"] != POLICY_LIMITATIONS:
        raise ValueError("LureAttest trust policy limitations are not canonical")
    builder_by_id = {item["builder_id"]: item for item in builders}
    expected_attestations = _artifact_attestations(reviewed_plan)
    expectation_by_id = {item["attestation_id"]: item for item in expectations}
    if set(expectation_by_id) != set(expected_attestations):
        raise ValueError("trust policy must cover every artifact attestation exactly once")
    used_builders = {item[1]["builder_id"] for item in expected_attestations.values()}
    if set(builder_by_id) != used_builders:
        raise ValueError("trust policy builders must exactly match artifact-plan builders")
    for attestation_id, (_, attestation) in expected_attestations.items():
        builder = builder_by_id[attestation["builder_id"]]
        expectation = expectation_by_id[attestation_id]
        if expectation["public_key_sha256"] != builder["public_key_sha256"]:
            raise ValueError("attestation signer is not bound to its claimed builder")
        if expectation["minimum_slsa_build_level"] > builder[
            "maximum_trusted_slsa_build_level"
        ]:
            raise ValueError("required SLSA level exceeds reviewed builder trust")
    return dict(policy)


def _planned_attestation(value: Any, field: str) -> Dict[str, Any]:
    item = _exact(
        value,
        field,
        (
            "attestation_id",
            "evidence_file",
            "subject_artifact_id",
            "subject_sha256",
            "statement_sha256",
            "statement_type",
            "predicate_type",
            "builder_id",
            "build_type",
            "source_uri",
            "source_sha256",
            "external_parameters_sha256",
            "public_key_sha256",
            "minimum_slsa_build_level",
        ),
    )
    attestation_id = _id(item["attestation_id"], f"{field}.attestation_id")
    if item["evidence_file"] != f"{attestation_id}.dsse.json":
        raise ValueError(f"{field}.evidence_file is not the canonical safe filename")
    _id(item["subject_artifact_id"], f"{field}.subject_artifact_id")
    for name in (
        "subject_sha256",
        "statement_sha256",
        "source_sha256",
        "external_parameters_sha256",
        "public_key_sha256",
    ):
        _digest(item[name], f"{field}.{name}")
    if item["statement_type"] != IN_TOTO_STATEMENT_TYPE:
        raise ValueError(f"{field}.statement_type is unsupported")
    if item["predicate_type"] != SLSA_PREDICATE_TYPE:
        raise ValueError(f"{field}.predicate_type is unsupported")
    for name in ("builder_id", "build_type", "source_uri"):
        _uri(item[name], f"{field}.{name}")
    _level(item["minimum_slsa_build_level"], f"{field}.minimum_slsa_build_level")
    return dict(item)


def validate_attest_plan(value: Any) -> Dict[str, Any]:
    plan = _exact(
        value,
        "LureAttest plan",
        (
            "schema",
            "schema_version",
            "plan_id",
            "created_at",
            "artifact_plan",
            "trust_policy",
            "trusted_builders",
            "workloads",
            "requirements",
            "limitations",
        ),
    )
    if plan["schema"] != PLAN_SCHEMA or plan["schema_version"] != 1:
        raise ValueError("unsupported LureAttest plan schema")
    _id(plan["plan_id"], "LureAttest plan.plan_id")
    _timestamp(plan["created_at"], "LureAttest plan.created_at")
    artifact_ref = _exact(plan["artifact_plan"], "artifact_plan", ("plan_id", "sha256"))
    policy_ref = _exact(plan["trust_policy"], "trust_policy", ("policy_id", "sha256"))
    _id(artifact_ref["plan_id"], "artifact_plan.plan_id")
    _digest(artifact_ref["sha256"], "artifact_plan.sha256")
    _id(policy_ref["policy_id"], "trust_policy.policy_id")
    _digest(policy_ref["sha256"], "trust_policy.sha256")
    builders = _trusted_builders(plan["trusted_builders"], "trusted_builders")
    workloads = _bounded_list(plan["workloads"], "workloads", 128)
    workload_ids: list[str] = []
    attestations: list[Dict[str, Any]] = []
    for index, workload_value in enumerate(workloads):
        workload = _exact(
            workload_value, f"workloads[{index}]", ("workload_principal_id", "attestations")
        )
        workload_ids.append(_id(workload["workload_principal_id"], "workload principal"))
        attestations.extend(
            _planned_attestation(item, f"workloads[{index}].attestations[{item_index}]")
            for item_index, item in enumerate(
                _bounded_list(workload["attestations"], "workload attestations", 3)
            )
        )
    if len(workload_ids) != len(set(workload_ids)):
        raise ValueError("LureAttest plan contains duplicate workloads")
    ids = [item["attestation_id"] for item in attestations]
    if len(ids) != len(set(ids)) or len(ids) > MAX_ATTESTATIONS:
        raise ValueError("LureAttest plan contains duplicate or excessive attestations")
    builders_by_id = {item["builder_id"]: item for item in builders}
    for item in attestations:
        builder = builders_by_id.get(item["builder_id"])
        if builder is None or builder["public_key_sha256"] != item["public_key_sha256"]:
            raise ValueError("planned attestation is not bound to its builder trust key")
        if item["minimum_slsa_build_level"] > builder["maximum_trusted_slsa_build_level"]:
            raise ValueError("planned attestation exceeds reviewed builder trust")
    _requirements(plan["requirements"], "requirements")
    if plan["limitations"] != PLAN_LIMITATIONS:
        raise ValueError("LureAttest plan limitations are not canonical")
    return dict(plan)


def compose_attest_plan(
    artifact_plan: Mapping[str, Any], trust_policy: Mapping[str, Any]
) -> Dict[str, Any]:
    reviewed_artifact_plan = validate_artifact_plan(artifact_plan)
    reviewed_policy = validate_trust_policy(trust_policy, reviewed_artifact_plan)
    expectation_by_id = {
        item["attestation_id"]: item
        for item in reviewed_policy["attestation_expectations"]
    }
    workloads = []
    for workload in sorted(
        reviewed_artifact_plan["workloads"], key=lambda item: item["workload_principal_id"]
    ):
        planned = []
        for attestation in sorted(
            workload["attestations"], key=lambda item: item["attestation_id"]
        ):
            expectation = expectation_by_id[attestation["attestation_id"]]
            planned.append(
                {
                    "attestation_id": attestation["attestation_id"],
                    "evidence_file": f"{attestation['attestation_id']}.dsse.json",
                    "subject_artifact_id": attestation["subject_artifact_id"],
                    "subject_sha256": attestation["subject_sha256"],
                    "statement_sha256": attestation["statement_sha256"],
                    "statement_type": attestation["statement_type"],
                    "predicate_type": attestation["predicate_type"],
                    "builder_id": attestation["builder_id"],
                    "build_type": attestation["build_type"],
                    "source_uri": expectation["source_uri"],
                    "source_sha256": attestation["source_sha256"],
                    "external_parameters_sha256": expectation[
                        "external_parameters_sha256"
                    ],
                    "public_key_sha256": expectation["public_key_sha256"],
                    "minimum_slsa_build_level": expectation[
                        "minimum_slsa_build_level"
                    ],
                }
            )
        workloads.append(
            {
                "workload_principal_id": workload["workload_principal_id"],
                "attestations": planned,
            }
        )
    return validate_attest_plan(
        {
            "schema": PLAN_SCHEMA,
            "schema_version": 1,
            "plan_id": reviewed_policy["policy_id"],
            "created_at": reviewed_policy["created_at"],
            "artifact_plan": {
                "plan_id": reviewed_artifact_plan["plan_id"],
                "sha256": _sha256(_canonical(reviewed_artifact_plan)),
            },
            "trust_policy": {
                "policy_id": reviewed_policy["policy_id"],
                "sha256": _sha256(_canonical(reviewed_policy)),
            },
            "trusted_builders": sorted(
                reviewed_policy["trusted_builders"], key=lambda item: item["builder_id"]
            ),
            "workloads": workloads,
            "requirements": dict(REQUIREMENTS),
            "limitations": list(PLAN_LIMITATIONS),
        }
    )


def _decode_base64(value: Any, field: str, maximum: int) -> bytes:
    if not isinstance(value, str) or len(value) > (maximum * 4 // 3) + 8:
        raise ValueError(f"{field} must be bounded base64")
    if len(value.rstrip("=")) % 4 == 1:
        raise ValueError(f"{field} is not valid base64")
    pattern = _B64URL if ("-" in value or "_" in value) else _B64
    if pattern.fullmatch(value) is None:
        raise ValueError(f"{field} is not valid base64")
    padded = value.rstrip("=") + "=" * (-len(value.rstrip("=")) % 4)
    try:
        decoded = base64.b64decode(
            padded.encode("ascii"), altchars=b"-_" if pattern is _B64URL else None, validate=True
        )
    except (ValueError, binascii.Error) as exc:
        raise ValueError(f"{field} is not valid base64") from exc
    if len(decoded) > maximum:
        raise ValueError(f"{field} exceeds its decoded byte limit")
    return decoded


def _public_key(raw: bytes, field: str) -> tuple[str, ec.EllipticCurvePublicKey]:
    if len(raw) > MAX_PUBLIC_KEY_BYTES:
        raise ValueError(f"{field} exceeds the public-key byte limit")
    try:
        key = serialization.load_pem_public_key(raw)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{field} is not a valid PEM public key") from exc
    if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(
        key.curve, ec.SECP256R1
    ):
        raise ValueError(f"{field} must be an ECDSA P-256 public key")
    der = key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return hashlib.sha256(der).hexdigest(), key


def public_key_sha256(public_key_pem: bytes) -> str:
    """Return the LureAttest SHA-256 fingerprint of a P-256 SPKI DER key."""
    return _public_key(public_key_pem, "public key")[0]


def external_parameters_sha256(payload: bytes) -> str:
    """Strictly parse an externalParameters object and commit to canonical JSON."""
    value = _strict(payload, "externalParameters")
    return _sha256(_canonical(_mapping(value, "externalParameters")))


def _pae(payload_type: str, payload: bytes) -> bytes:
    encoded_type = payload_type.encode("utf-8")
    return b"DSSEv1 %d " % len(encoded_type) + encoded_type + b" %d " % len(payload) + payload


def _mapping(value: Any, field: str) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{field} must be an object")
    return value


def _verify_statement(statement: Any, payload: bytes, expected: Mapping[str, Any]) -> None:
    statement_map = _mapping(statement, "in-toto statement")
    if statement_map.get("_type") != expected["statement_type"]:
        raise ValueError("in-toto statement type does not match the plan")
    if statement_map.get("predicateType") != expected["predicate_type"]:
        raise ValueError("SLSA predicate type does not match the plan")
    if _sha256(payload) != expected["statement_sha256"]:
        raise ValueError("authenticated statement bytes do not match statement_sha256")

    subjects = statement_map.get("subject")
    if not isinstance(subjects, list) or len(subjects) != 1:
        raise ValueError("LureAttest requires exactly one in-toto subject")
    subject = _mapping(subjects[0], "in-toto subject")
    digest = _mapping(subject.get("digest"), "in-toto subject.digest")
    if digest.get("sha256") != expected["subject_sha256"]:
        raise ValueError("in-toto subject SHA-256 does not match the artifact plan")

    predicate = _mapping(statement_map.get("predicate"), "SLSA predicate")
    definition = _mapping(predicate.get("buildDefinition"), "SLSA buildDefinition")
    details = _mapping(predicate.get("runDetails"), "SLSA runDetails")
    builder = _mapping(details.get("builder"), "SLSA builder")
    if builder.get("id") != expected["builder_id"]:
        raise ValueError("authenticated signer is not paired with the expected builder.id")
    if definition.get("buildType") != expected["build_type"]:
        raise ValueError("SLSA buildType does not match the reviewed expectation")
    external_parameters = _mapping(
        definition.get("externalParameters"), "SLSA externalParameters"
    )
    if _sha256(_canonical(external_parameters)) != expected["external_parameters_sha256"]:
        raise ValueError("SLSA externalParameters do not match the reviewed commitment")
    dependencies = definition.get("resolvedDependencies")
    if not isinstance(dependencies, list) or len(dependencies) > MAX_DEPENDENCIES:
        raise ValueError("SLSA resolvedDependencies must be a bounded array")
    matches = 0
    for index, dependency_value in enumerate(dependencies):
        dependency = _mapping(dependency_value, f"resolvedDependencies[{index}]")
        dependency_digest = dependency.get("digest")
        if dependency.get("uri") == expected["source_uri"] and isinstance(
            dependency_digest, dict
        ) and dependency_digest.get("sha256") == expected["source_sha256"]:
            matches += 1
    if matches != 1:
        raise ValueError("SLSA provenance must contain one exact source URI and digest match")


def _verify_envelope(
    raw: bytes,
    expected: Mapping[str, Any],
    key: ec.EllipticCurvePublicKey,
) -> Dict[str, Any]:
    envelope = _strict(raw, expected["evidence_file"])
    envelope_map = _exact(
        envelope, expected["evidence_file"], ("payloadType", "payload", "signatures")
    )
    if envelope_map["payloadType"] != DSSE_PAYLOAD_TYPE:
        raise ValueError("DSSE payloadType is unsupported")
    signatures = envelope_map["signatures"]
    if not isinstance(signatures, list) or len(signatures) != 1:
        raise ValueError("LureAttest requires exactly one DSSE signature")
    signature = signatures[0]
    if not isinstance(signature, dict) or set(signature) not in ({"sig"}, {"keyid", "sig"}):
        raise ValueError("DSSE signature entry has an unsupported shape")
    if "keyid" in signature and (
        not isinstance(signature["keyid"], str) or len(signature["keyid"]) > 512
    ):
        raise ValueError("DSSE keyid must be a bounded string hint")
    payload = _decode_base64(envelope_map["payload"], "DSSE payload", MAX_PAYLOAD_BYTES)
    signature_bytes = _decode_base64(signature["sig"], "DSSE signature", 512)
    try:
        key.verify(signature_bytes, _pae(DSSE_PAYLOAD_TYPE, payload), ec.ECDSA(hashes.SHA256()))
    except InvalidSignature as exc:
        raise ValueError("DSSE signature verification failed") from exc
    statement = _strict(payload, "authenticated DSSE payload")
    _verify_statement(statement, payload, expected)
    return {
        "attestation_id": expected["attestation_id"],
        "evidence_file": expected["evidence_file"],
        "envelope_sha256": _sha256(raw),
        "statement_sha256": _sha256(payload),
        "subject_artifact_id": expected["subject_artifact_id"],
        "subject_sha256": expected["subject_sha256"],
        "builder_id": expected["builder_id"],
        "build_type": expected["build_type"],
        "source_uri": expected["source_uri"],
        "source_sha256": expected["source_sha256"],
        "external_parameters_sha256": expected["external_parameters_sha256"],
        "public_key_sha256": expected["public_key_sha256"],
        "policy_slsa_build_level": expected["minimum_slsa_build_level"],
        "authenticated": True,
        "expectations_satisfied": True,
    }


def _time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _verification_value(
    artifact_plan: Mapping[str, Any],
    trust_policy: Mapping[str, Any],
    plan: Mapping[str, Any],
    public_key_values: Sequence[bytes],
    evidence_values: Mapping[str, bytes],
    verified_at: str,
) -> Dict[str, Any]:
    reviewed_artifact_plan = validate_artifact_plan(artifact_plan)
    reviewed_policy = validate_trust_policy(trust_policy, reviewed_artifact_plan)
    independently_derived = compose_attest_plan(reviewed_artifact_plan, reviewed_policy)
    reviewed_plan = validate_attest_plan(plan)
    if reviewed_plan != independently_derived:
        raise ValueError("LureAttest plan does not match independently derived sources")
    _timestamp(verified_at, "LureAttest verification.verified_at")
    if _time(verified_at) < max(
        _time(reviewed_artifact_plan["created_at"]),
        _time(reviewed_policy["created_at"]),
        _time(reviewed_plan["created_at"]),
    ):
        raise ValueError("LureAttest verification predates its source evidence")

    if not 1 <= len(public_key_values) <= MAX_BUILDERS:
        raise ValueError("trusted public keys must be a non-empty bounded sequence")
    keys: dict[str, tuple[bytes, ec.EllipticCurvePublicKey]] = {}
    for index, raw in enumerate(public_key_values):
        fingerprint, key = _public_key(raw, f"public key {index}")
        if fingerprint in keys:
            raise ValueError("duplicate trusted public key supplied")
        keys[fingerprint] = (raw, key)
    required_keys = {item["public_key_sha256"] for item in reviewed_plan["trusted_builders"]}
    if set(keys) != required_keys:
        raise ValueError("supplied public keys must exactly match the reviewed trust policy")

    planned = [
        (workload["workload_principal_id"], item)
        for workload in reviewed_plan["workloads"]
        for item in workload["attestations"]
    ]
    expected_files = {item["evidence_file"] for _, item in planned}
    if set(evidence_values) != expected_files:
        raise ValueError("evidence directory must contain exactly the planned DSSE files")
    results = []
    for workload_id, item in planned:
        raw = evidence_values[item["evidence_file"]]
        if len(raw) > MAX_ENVELOPE_BYTES:
            raise ValueError(f"{item['evidence_file']} exceeds the envelope byte limit")
        result = _verify_envelope(raw, item, keys[item["public_key_sha256"]][1])
        result["workload_principal_id"] = workload_id
        results.append(result)

    embedded_keys = [
        {
            "public_key_sha256": fingerprint,
            "pem_sha256": _sha256(raw),
            "pem_base64": base64.b64encode(raw).decode("ascii"),
        }
        for fingerprint, (raw, _) in sorted(keys.items())
    ]
    embedded_evidence = [
        {
            "attestation_id": item["attestation_id"],
            "evidence_file": item["evidence_file"],
            "envelope_sha256": _sha256(evidence_values[item["evidence_file"]]),
            "envelope_base64": base64.b64encode(
                evidence_values[item["evidence_file"]]
            ).decode("ascii"),
        }
        for _, item in planned
    ]
    levels = [item["minimum_slsa_build_level"] for _, item in planned]
    return {
        "schema": VERIFICATION_SCHEMA,
        "schema_version": 1,
        "verified_at": verified_at,
        "implementation": {"name": "lurescope", "version": __version__},
        "artifact_plan": reviewed_artifact_plan,
        "trust_policy": reviewed_policy,
        "plan": reviewed_plan,
        "digests": {
            "artifact_plan_sha256": _sha256(_canonical(reviewed_artifact_plan)),
            "trust_policy_sha256": _sha256(_canonical(reviewed_policy)),
            "plan_sha256": _sha256(_canonical(reviewed_plan)),
        },
        "public_keys": embedded_keys,
        "evidence": embedded_evidence,
        "results": results,
        "summary": {
            "workload_count": len(reviewed_plan["workloads"]),
            "attestation_count": len(results),
            "authenticated_attestation_count": len(results),
            "expectation_match_count": len(results),
            "minimum_policy_slsa_build_level": min(levels),
            "finding_count": 0,
            "verdict": "pass",
        },
        "checks": [
            {"check_id": check_id, "status": "pass"}
            for check_id in VERIFICATION_CHECKS
        ],
        "overall_status": "pass",
        "limitations": list(VERIFICATION_LIMITATIONS),
    }


def _read_evidence_directory(path: Path, expected_files: set[str]) -> Dict[str, bytes]:
    root = Path(path)
    if root.is_symlink() or not root.is_dir():
        raise ValueError("evidence path must be a regular local directory")
    actual = set()
    for item in root.iterdir():
        actual.add(item.name)
        if len(actual) > len(expected_files):
            raise ValueError("evidence directory contains more files than the plan")
    if actual != expected_files:
        raise ValueError("evidence directory must contain exactly the planned DSSE files")
    result = {}
    for name in sorted(expected_files):
        target = root / name
        if target.is_symlink() or not target.is_file():
            raise ValueError(f"{name} must be a regular non-symlink file")
        if target.stat().st_size > MAX_ENVELOPE_BYTES:
            raise ValueError(f"{name} exceeds the envelope byte limit")
        result[name] = target.read_bytes()
    return result


def create_attest_verification(
    artifact_plan_path: Path,
    trust_policy_path: Path,
    plan_path: Path,
    evidence_directory: Path,
    public_key_paths: Sequence[Path],
    output_path: Optional[Path] = None,
    *,
    verified_at: Optional[str] = None,
) -> Dict[str, Any]:
    artifact_plan = validate_artifact_plan(
        _strict(_read(Path(artifact_plan_path)), "artifact plan")
    )
    policy = validate_trust_policy(
        _strict(_read(Path(trust_policy_path)), "LureAttest trust policy"), artifact_plan
    )
    plan = validate_attest_plan(_strict(_read(Path(plan_path)), "LureAttest plan"))
    expected_files = {
        item["evidence_file"]
        for workload in plan["workloads"]
        for item in workload["attestations"]
    }
    evidence = _read_evidence_directory(Path(evidence_directory), expected_files)
    public_keys = [_read(Path(path)) for path in public_key_paths]
    result = _verification_value(
        artifact_plan,
        policy,
        plan,
        public_keys,
        evidence,
        verified_at or _timestamp_now(),
    )
    if output_path is not None:
        _write_new(Path(output_path), _canonical(result))
    return result


def validate_attest_verification(value: Any) -> Dict[str, Any]:
    verification = _exact(
        value,
        "LureAttest verification",
        (
            "schema",
            "schema_version",
            "verified_at",
            "implementation",
            "artifact_plan",
            "trust_policy",
            "plan",
            "digests",
            "public_keys",
            "evidence",
            "results",
            "summary",
            "checks",
            "overall_status",
            "limitations",
        ),
    )
    if verification["schema"] != VERIFICATION_SCHEMA or verification["schema_version"] != 1:
        raise ValueError("unsupported LureAttest verification schema")
    implementation = _exact(verification["implementation"], "implementation", ("name", "version"))
    if implementation["name"] != "lurescope" or not isinstance(
        implementation["version"], str
    ):
        raise ValueError("unsupported LureAttest verifier implementation")
    key_values = []
    for index, item_value in enumerate(
        _bounded_list(verification["public_keys"], "public_keys", MAX_BUILDERS)
    ):
        item = _exact(
            item_value,
            f"public_keys[{index}]",
            ("public_key_sha256", "pem_sha256", "pem_base64"),
        )
        _digest(item["public_key_sha256"], "public key fingerprint")
        _digest(item["pem_sha256"], "public key PEM digest")
        raw = _decode_base64(item["pem_base64"], "public key PEM", MAX_PUBLIC_KEY_BYTES)
        if _sha256(raw) != item["pem_sha256"]:
            raise ValueError("embedded public-key PEM digest mismatch")
        key_values.append(raw)
    evidence_values: Dict[str, bytes] = {}
    for index, item_value in enumerate(
        _bounded_list(verification["evidence"], "evidence", MAX_ATTESTATIONS)
    ):
        item = _exact(
            item_value,
            f"evidence[{index}]",
            ("attestation_id", "evidence_file", "envelope_sha256", "envelope_base64"),
        )
        _id(item["attestation_id"], "embedded attestation_id")
        _digest(item["envelope_sha256"], "embedded envelope digest")
        raw = _decode_base64(item["envelope_base64"], "embedded envelope", MAX_ENVELOPE_BYTES)
        if _sha256(raw) != item["envelope_sha256"]:
            raise ValueError("embedded DSSE envelope digest mismatch")
        filename = item["evidence_file"]
        if not isinstance(filename, str) or filename in evidence_values:
            raise ValueError("embedded DSSE evidence filename is invalid or duplicated")
        evidence_values[filename] = raw
    expected = _verification_value(
        verification["artifact_plan"],
        verification["trust_policy"],
        verification["plan"],
        key_values,
        evidence_values,
        verification["verified_at"],
    )
    expected["implementation"]["version"] = implementation["version"]
    if verification != expected:
        raise ValueError("LureAttest verification does not independently recompute")
    return dict(verification)


def load_attest_verification(path: Path) -> Dict[str, Any]:
    return validate_attest_verification(
        _strict(_read(Path(path), private=True), "LureAttest verification")
    )
