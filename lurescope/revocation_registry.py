"""Signed append-only registry for privacy-minimized LureRevoke checkpoints.

The registry uses the SHA-256 Merkle Tree Hash construction from RFC 9162 to
commit an ordered sequence of small registration records.  Every append also
creates a P-256 DSSE-authenticated in-toto tree head.  It is inspired by
transparency systems but is not a SCITT Transparency Service, COSE Receipt, or
RFC 9942 Verifiable Data Structure implementation.
"""

from __future__ import annotations

import hashlib
import os
import secrets
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Mapping, Optional, Sequence

from . import __version__
from .boundary import (
    _private_key,
    _private_key_id,
    _sign_statement,
    _verify_envelope,
    public_key_id,
)
from .permit import (
    STATEMENT_TYPE,
    _canonical,
    _digest,
    _exact,
    _id,
    _integer,
    _portable_id,
    _read,
    _sha256,
    _strict,
    _timestamp,
    _timestamp_now,
    _write_new,
)
from .revocation import verify_revocation_bundle

REGISTRY_SCHEMA = "https://github.com/immu4989/lurescope/spec/lurerevoke-registry/v1"
ENTRY_SCHEMA = "https://github.com/immu4989/lurescope/spec/lurerevoke-registry-entry/v1"
TREE_HEAD_PREDICATE = "https://github.com/immu4989/lurescope/spec/lurerevoke-registry-tree-head/v1"
INCLUSION_PROOF_SCHEMA = (
    "https://github.com/immu4989/lurescope/spec/lurerevoke-registry-inclusion-proof/v1"
)
CONSISTENCY_PROOF_SCHEMA = (
    "https://github.com/immu4989/lurescope/spec/lurerevoke-registry-consistency-proof/v1"
)
HEAD_COMPARISON_SCHEMA = (
    "https://github.com/immu4989/lurescope/spec/lurerevoke-registry-head-comparison/v1"
)
HASH_PROFILE = "rfc9162-sha256-merkle-tree"
CONFIG_FILE = "registry.json"
ENTRIES_DIRECTORY = "entries"
ENTRY_FILE = "entry.json"
STATEMENT_FILE = "tree-head.statement.json"
DSSE_FILE = "tree-head.dsse.json"
MAX_ENTRIES = 10_000

LIMITATIONS = [
    "registry_contains_checkpoint_digests_status_time_and_receiver_version_metadata_only",
    "signed_tree_heads_detect_mutation_deletion_or_reordering_within_the_available_history",
    "tail_deletion_requires_a_previously_retained_or_independently_witnessed_tree_head",
    "registration_does_not_prove_event_observation_receiver_clock_or_enforcement_authenticity",
    "registry_is_not_an_rfc9943_transparency_service_rfc9942_vds_or_compliance_claim",
]
INTERPRETATION = (
    "A valid registry proves that its available registration records form the ordered Merkle "
    "history committed by each authenticated tree head. A separately retained tree head can "
    "detect rollback. Registration does not prove the underlying revocation evidence is complete, "
    "deployed, or authentic beyond its bundle key."
)
INCLUSION_PROOF_LIMITATIONS = [
    "proof_authenticates_inclusion_of_one_privacy_minimized_entry_in_one_signed_tree_head",
    "proof_does_not_disclose_other_registry_entries_or_the_revocation_evaluation",
    "proof_does_not_establish_global_non_equivocation_or_append_only_consistency",
    "proof_does_not_prove_event_observation_receiver_clock_or_enforcement_authenticity",
    "proof_is_not_an_rfc9943_receipt_rfc9942_vds_or_compliance_claim",
]
INCLUSION_PROOF_INTERPRETATION = (
    "A valid proof establishes that the exact privacy-minimized entry is a leaf in the "
    "RFC 9162-style Merkle tree committed by the embedded authenticated tree head. It does not "
    "establish consistency with another tree head, global non-equivocation, or the truth and "
    "completeness of the underlying revocation observations."
)
CONSISTENCY_PROOF_LIMITATIONS = [
    "proof_authenticates_that_one_signed_tree_head_is_a_prefix_of_another",
    "proof_discloses_merkle_nodes_and_signed_heads_but_no_registry_entries_or_evaluations",
    "proof_does_not_establish_global_non_equivocation_across_uncompared_tree_heads",
    "proof_does_not_prove_event_observation_receiver_clock_or_enforcement_authenticity",
    "proof_is_not_an_rfc9943_receipt_rfc9942_vds_or_compliance_claim",
]
CONSISTENCY_PROOF_INTERPRETATION = (
    "A valid proof establishes that the entry sequence committed by the first authenticated "
    "tree head is an exact prefix of the sequence committed by the second authenticated tree "
    "head. It does not rule out a conflicting head that was not compared or prove the truth and "
    "completeness of underlying revocation observations."
)
HEAD_COMPARISON_LIMITATIONS = [
    "comparison_authenticates_only_the_two_presented_heads_under_one_registry_key",
    "same_size_different_statements_are_equivocation_evidence_not_attribution_of_cause",
    "different_tree_sizes_require_a_separate_consistency_proof",
    "unpresented_conflicting_heads_and_global_non_equivocation_are_not_established",
    "comparison_does_not_prove_underlying_revocation_observation_or_enforcement_authenticity",
]
HEAD_COMPARISON_INTERPRETATION = (
    "Identical means both authenticated envelopes carry the same canonical tree-head statement. "
    "Equivocation means the same registry key authenticated different statements for the same "
    "tree size. Different sizes are deliberately inconclusive until a consistency proof is "
    "verified."
)


def _time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _private_directory(path: Path, label: str) -> Path:
    target = Path(path)
    if (
        target.is_symlink()
        or not target.is_dir()
        or (os.name == "posix" and target.stat().st_mode & 0o077)
    ):
        raise ValueError(f"{label} must be a private regular directory")
    return target


def _validate_config(value: Any) -> Dict[str, Any]:
    config = _exact(
        value,
        "revocation registry",
        (
            "schema",
            "schema_version",
            "registry_id",
            "created_at",
            "producer",
            "registration_policy",
            "hash_profile",
            "signer_key_id",
            "limitations",
            "interpretation_boundary",
        ),
    )
    if config["schema"] != REGISTRY_SCHEMA or config["schema_version"] != 1:
        raise ValueError("unsupported LureRevoke registry schema")
    _portable_id(config["registry_id"], "registry.registry_id")
    _timestamp(config["created_at"], "registry.created_at")
    producer = _exact(config["producer"], "registry.producer", ("name", "version"))
    if producer["name"] != "lurescope":
        raise ValueError("registry producer must be lurescope")
    _id(producer["version"], "registry.producer.version")
    policy = _exact(
        config["registration_policy"],
        "registry.registration_policy",
        ("system_id", "environment", "receiver_name", "require_authenticated_bundle"),
    )
    _id(policy["system_id"], "registration_policy.system_id")
    if policy["environment"] not in {"development", "evaluation", "staging", "production"}:
        raise ValueError("registry environment is unsupported")
    _id(policy["receiver_name"], "registration_policy.receiver_name")
    if policy["require_authenticated_bundle"] is not True:
        raise ValueError("registry must require authenticated bundles")
    if config["hash_profile"] != HASH_PROFILE:
        raise ValueError("registry hash profile is unsupported")
    _digest(config["signer_key_id"], "registry.signer_key_id")
    if config["limitations"] != LIMITATIONS or config["interpretation_boundary"] != INTERPRETATION:
        raise ValueError("registry interpretation boundary is invalid")
    return dict(config)


def _validate_entry(value: Any, *, config: Mapping[str, Any], sequence: int) -> Dict[str, Any]:
    entry = _exact(
        value,
        "revocation registry entry",
        (
            "schema",
            "schema_version",
            "registry_id",
            "sequence",
            "registered_at",
            "previous_entry_sha256",
            "system",
            "receiver",
            "evidence",
            "privacy",
            "limitations",
        ),
    )
    if entry["schema"] != ENTRY_SCHEMA or entry["schema_version"] != 1:
        raise ValueError("unsupported LureRevoke registry entry schema")
    if entry["registry_id"] != config["registry_id"]:
        raise ValueError("registry entry names a different registry")
    _integer(entry["sequence"], "entry.sequence", 1, MAX_ENTRIES)
    if entry["sequence"] != sequence:
        raise ValueError("registry entry sequence is not contiguous")
    _timestamp(entry["registered_at"], "entry.registered_at")
    if entry["previous_entry_sha256"] is not None:
        _digest(entry["previous_entry_sha256"], "entry.previous_entry_sha256")
    system = _exact(entry["system"], "entry.system", ("system_id", "environment"))
    policy = config["registration_policy"]
    if system != {"system_id": policy["system_id"], "environment": policy["environment"]}:
        raise ValueError("registry entry violates its system registration policy")
    receiver = _exact(
        entry["receiver"],
        "entry.receiver",
        ("name", "version", "artifact_sha256", "bundle_signer_key_id"),
    )
    if receiver["name"] != policy["receiver_name"]:
        raise ValueError("registry entry violates its receiver registration policy")
    _id(receiver["version"], "entry.receiver.version")
    for field in ("artifact_sha256", "bundle_signer_key_id"):
        if receiver[field] is not None:
            _digest(receiver[field], f"entry.receiver.{field}")
    if receiver["bundle_signer_key_id"] is None:
        raise ValueError("registry entry must bind an authenticated bundle signer")
    evidence = _exact(
        entry["evidence"],
        "entry.evidence",
        (
            "manifest_sha256",
            "checkpoint_sha256",
            "plan_sha256",
            "run_sha256",
            "evaluation_generated_at",
            "overall_status",
        ),
    )
    for field in ("manifest_sha256", "checkpoint_sha256", "plan_sha256", "run_sha256"):
        _digest(evidence[field], f"entry.evidence.{field}")
    _timestamp(evidence["evaluation_generated_at"], "entry.evidence.evaluation_generated_at")
    if evidence["overall_status"] not in {"pass", "fail"}:
        raise ValueError("registry entry status is unsupported")
    if entry["privacy"] != {
        "contains_revocation_evaluation": False,
        "contains_subject_or_event_identifiers": False,
        "contains_tokens_credentials_prompts_payloads_or_targets": False,
    }:
        raise ValueError("registry entry privacy boundary is invalid")
    if entry["limitations"] != LIMITATIONS:
        raise ValueError("registry entry limitations are invalid")
    return dict(entry)


def _leaf_hash(entry_raw: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + entry_raw).digest()


def _node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def _frontier_add(frontier: list[Optional[bytes]], leaf: bytes) -> None:
    level = 0
    current = leaf
    while level < len(frontier) and frontier[level] is not None:
        current = _node_hash(frontier[level], current)  # type: ignore[arg-type]
        frontier[level] = None
        level += 1
    if level == len(frontier):
        frontier.append(current)
    else:
        frontier[level] = current


def _frontier_root(frontier: Sequence[Optional[bytes]]) -> bytes:
    current: Optional[bytes] = None
    for node in frontier:
        if node is not None:
            current = node if current is None else _node_hash(node, current)
    return hashlib.sha256(b"").digest() if current is None else current


def _split_size(size: int) -> int:
    if size <= 1:
        raise ValueError("Merkle subtree must contain at least two leaves")
    return 1 << ((size - 1).bit_length() - 1)


def _merkle_root(entry_raws: Sequence[bytes]) -> bytes:
    if not entry_raws:
        return hashlib.sha256(b"").digest()
    if len(entry_raws) == 1:
        return _leaf_hash(entry_raws[0])
    split = _split_size(len(entry_raws))
    return _node_hash(_merkle_root(entry_raws[:split]), _merkle_root(entry_raws[split:]))


def _inclusion_path(leaf_index: int, entry_raws: Sequence[bytes]) -> list[bytes]:
    if leaf_index < 0 or leaf_index >= len(entry_raws):
        raise ValueError("leaf index is outside the Merkle tree")
    if len(entry_raws) == 1:
        return []
    split = _split_size(len(entry_raws))
    if leaf_index < split:
        return [
            *_inclusion_path(leaf_index, entry_raws[:split]),
            _merkle_root(entry_raws[split:]),
        ]
    return [
        *_inclusion_path(leaf_index - split, entry_raws[split:]),
        _merkle_root(entry_raws[:split]),
    ]


def _verify_inclusion_path(
    leaf_hash: bytes,
    *,
    leaf_index: int,
    tree_size: int,
    inclusion_path: Sequence[bytes],
) -> bytes:
    """Recompute a root with the RFC 9162 Section 2.1.3.2 algorithm."""
    if tree_size < 1 or leaf_index < 0 or leaf_index >= tree_size:
        raise ValueError("inclusion proof leaf index is outside the tree")
    fn = leaf_index
    sn = tree_size - 1
    root = leaf_hash
    for sibling in inclusion_path:
        if len(sibling) != hashlib.sha256().digest_size or sn == 0:
            raise ValueError("inclusion proof path is malformed or overlong")
        if fn & 1 or fn == sn:
            root = _node_hash(sibling, root)
            if not fn & 1:
                while fn != 0 and not fn & 1:
                    fn >>= 1
                    sn >>= 1
        else:
            root = _node_hash(root, sibling)
        fn >>= 1
        sn >>= 1
    if sn != 0:
        raise ValueError("inclusion proof path is incomplete")
    return root


def _consistency_path(first_size: int, entry_raws: Sequence[bytes]) -> list[bytes]:
    second_size = len(entry_raws)
    if first_size < 1 or first_size >= second_size:
        raise ValueError("consistency proof requires 0 < first tree size < second tree size")

    def subproof(size: int, leaves: Sequence[bytes], complete: bool) -> list[bytes]:
        if size == len(leaves):
            return [] if complete else [_merkle_root(leaves)]
        split = _split_size(len(leaves))
        if size <= split:
            return [*subproof(size, leaves[:split], complete), _merkle_root(leaves[split:])]
        return [
            *subproof(size - split, leaves[split:], False),
            _merkle_root(leaves[:split]),
        ]

    return subproof(first_size, entry_raws, True)


def _verify_consistency_path(
    first_hash: bytes,
    second_hash: bytes,
    *,
    first_size: int,
    second_size: int,
    consistency_path: Sequence[bytes],
) -> None:
    """Verify append-only extension with RFC 9162 Section 2.1.4.2."""
    if first_size < 1 or first_size >= second_size or second_size > MAX_ENTRIES:
        raise ValueError("consistency proof tree sizes are invalid")
    if not consistency_path:
        raise ValueError("consistency proof path cannot be empty")
    path = list(consistency_path)
    if first_size & (first_size - 1) == 0:
        path.insert(0, first_hash)
    fn = first_size - 1
    sn = second_size - 1
    if fn & 1:
        while fn & 1:
            fn >>= 1
            sn >>= 1
    first_root = path[0]
    second_root = path[0]
    for node in path[1:]:
        if len(node) != hashlib.sha256().digest_size or sn == 0:
            raise ValueError("consistency proof path is malformed or overlong")
        if fn & 1 or fn == sn:
            first_root = _node_hash(node, first_root)
            second_root = _node_hash(node, second_root)
            if not fn & 1:
                while fn != 0 and not fn & 1:
                    fn >>= 1
                    sn >>= 1
        else:
            second_root = _node_hash(second_root, node)
        fn >>= 1
        sn >>= 1
    if sn != 0 or first_root != first_hash or second_root != second_hash:
        raise ValueError("consistency proof path does not reconcile both tree roots")


def _tree_head(
    config: Mapping[str, Any],
    config_raw: bytes,
    entry: Mapping[str, Any],
    entry_raw: bytes,
    root_hash: str,
    previous_tree_head_sha256: Optional[str],
) -> Dict[str, Any]:
    return {
        "_type": STATEMENT_TYPE,
        "subject": [{"name": ENTRY_FILE, "digest": {"sha256": _sha256(entry_raw)}}],
        "predicateType": TREE_HEAD_PREDICATE,
        "predicate": {
            "registry_id": config["registry_id"],
            "tree_size": entry["sequence"],
            "root_sha256": root_hash,
            "latest_entry_sha256": _sha256(entry_raw),
            "previous_tree_head_sha256": previous_tree_head_sha256,
            "config_sha256": _sha256(config_raw),
            "registered_at": entry["registered_at"],
            "hash_profile": HASH_PROFILE,
            "signer_key_id": config["signer_key_id"],
            "limitations": list(LIMITATIONS),
            "interpretation_boundary": INTERPRETATION,
        },
    }


def _validate_tree_head(
    value: Any,
    *,
    config: Mapping[str, Any],
    config_raw: bytes,
    tree_size: int,
    root_sha256: str,
) -> Dict[str, Any]:
    statement = _exact(
        value,
        "registry proof tree head",
        ("_type", "subject", "predicateType", "predicate"),
    )
    if statement["_type"] != STATEMENT_TYPE or statement["predicateType"] != TREE_HEAD_PREDICATE:
        raise ValueError("registry proof carries an unsupported tree-head statement")
    subjects = statement["subject"]
    if not isinstance(subjects, list) or len(subjects) != 1:
        raise ValueError("registry proof tree head must name one latest entry")
    subject = _exact(subjects[0], "tree-head subject", ("name", "digest"))
    if subject["name"] != ENTRY_FILE:
        raise ValueError("registry proof tree-head subject is invalid")
    subject_digest = _exact(subject["digest"], "tree-head subject digest", ("sha256",))
    _digest(subject_digest["sha256"], "tree-head subject.digest.sha256")
    predicate = _exact(
        statement["predicate"],
        "registry proof tree-head predicate",
        (
            "registry_id",
            "tree_size",
            "root_sha256",
            "latest_entry_sha256",
            "previous_tree_head_sha256",
            "config_sha256",
            "registered_at",
            "hash_profile",
            "signer_key_id",
            "limitations",
            "interpretation_boundary",
        ),
    )
    if predicate["registry_id"] != config["registry_id"]:
        raise ValueError("registry proof tree head names a different registry")
    _integer(predicate["tree_size"], "tree-head tree size", 1, MAX_ENTRIES)
    if predicate["tree_size"] != tree_size:
        raise ValueError("registry proof tree size differs from its signed tree head")
    _digest(predicate["root_sha256"], "tree-head root_sha256")
    if predicate["root_sha256"] != root_sha256:
        raise ValueError("registry proof root differs from its signed tree head")
    _digest(predicate["latest_entry_sha256"], "tree-head latest_entry_sha256")
    if predicate["latest_entry_sha256"] != subject_digest["sha256"]:
        raise ValueError("tree-head latest entry does not match its subject")
    if predicate["previous_tree_head_sha256"] is not None:
        _digest(predicate["previous_tree_head_sha256"], "tree-head previous_tree_head_sha256")
    if predicate["config_sha256"] != _sha256(config_raw):
        raise ValueError("registry proof tree head does not bind its registry config")
    _timestamp(predicate["registered_at"], "tree-head registered_at")
    if predicate["hash_profile"] != HASH_PROFILE:
        raise ValueError("registry proof tree-head hash profile is unsupported")
    if predicate["signer_key_id"] != config["signer_key_id"]:
        raise ValueError("registry proof tree head names a different signer")
    if (
        predicate["limitations"] != LIMITATIONS
        or predicate["interpretation_boundary"] != INTERPRETATION
    ):
        raise ValueError("registry proof tree-head interpretation boundary is invalid")
    return dict(statement)


def _authenticated_tree_head(
    statement_value: Any,
    envelope_value: Any,
    *,
    config: Mapping[str, Any],
    config_raw: bytes,
    public_key_pem: bytes,
    label: str,
) -> tuple[Dict[str, Any], Dict[str, Any], bytes]:
    if not isinstance(statement_value, dict) or not isinstance(
        statement_value.get("predicate"), dict
    ):
        raise ValueError(f"{label} tree-head statement is malformed")
    predicate = statement_value["predicate"]
    tree_size = _integer(predicate.get("tree_size"), f"{label} tree size", 1, MAX_ENTRIES)
    root_sha256 = _digest(predicate.get("root_sha256"), f"{label} root_sha256")
    statement = _validate_tree_head(
        statement_value,
        config=config,
        config_raw=config_raw,
        tree_size=tree_size,
        root_sha256=root_sha256,
    )
    if not isinstance(envelope_value, dict):
        raise ValueError(f"{label} tree-head DSSE must be an object")
    envelope = dict(envelope_value)
    statement_raw = _canonical(statement)
    _verify_envelope(envelope, statement_raw, public_key_pem)
    return statement, envelope, statement_raw


def _head_comparison_value(
    config_value: Any,
    first_statement_value: Any,
    first_envelope_value: Any,
    second_statement_value: Any,
    second_envelope_value: Any,
    *,
    public_key_pem: bytes,
) -> Dict[str, Any]:
    config = _validate_config(config_value)
    config_raw = _canonical(config)
    if config["signer_key_id"] != public_key_id(public_key_pem):
        raise ValueError("head-comparison public key differs from its configured signer")
    first_statement, first_envelope, first_raw = _authenticated_tree_head(
        first_statement_value,
        first_envelope_value,
        config=config,
        config_raw=config_raw,
        public_key_pem=public_key_pem,
        label="first",
    )
    second_statement, second_envelope, second_raw = _authenticated_tree_head(
        second_statement_value,
        second_envelope_value,
        config=config,
        config_raw=config_raw,
        public_key_pem=public_key_pem,
        label="second",
    )
    first_predicate = first_statement["predicate"]
    second_predicate = second_statement["predicate"]
    same_size = first_predicate["tree_size"] == second_predicate["tree_size"]
    same_statement = secrets.compare_digest(first_raw, second_raw)
    same_root = secrets.compare_digest(
        first_predicate["root_sha256"], second_predicate["root_sha256"]
    )
    if same_size:
        status = "identical" if same_statement else "equivocation"
    else:
        status = "different_sizes_consistency_not_evaluated"
    return {
        "schema": HEAD_COMPARISON_SCHEMA,
        "schema_version": 1,
        "registry_config": config,
        "first": {
            "tree_head_statement": first_statement,
            "tree_head_dsse": first_envelope,
        },
        "second": {
            "tree_head_statement": second_statement,
            "tree_head_dsse": second_envelope,
        },
        "summary": {
            "first_tree_size": first_predicate["tree_size"],
            "first_root_sha256": first_predicate["root_sha256"],
            "first_statement_sha256": _sha256(first_raw),
            "second_tree_size": second_predicate["tree_size"],
            "second_root_sha256": second_predicate["root_sha256"],
            "second_statement_sha256": _sha256(second_raw),
            "same_tree_size": same_size,
            "same_root": same_root,
            "same_statement": same_statement,
            "status": status,
        },
        "limitations": list(HEAD_COMPARISON_LIMITATIONS),
        "interpretation_boundary": HEAD_COMPARISON_INTERPRETATION,
    }


def _validate_head_comparison(value: Any, *, public_key_pem: bytes) -> Dict[str, Any]:
    comparison = _exact(
        value,
        "revocation registry head comparison",
        (
            "schema",
            "schema_version",
            "registry_config",
            "first",
            "second",
            "summary",
            "limitations",
            "interpretation_boundary",
        ),
    )
    if comparison["schema"] != HEAD_COMPARISON_SCHEMA or comparison["schema_version"] != 1:
        raise ValueError("unsupported LureRevoke registry head-comparison schema")
    first = _exact(
        comparison["first"],
        "first compared head",
        ("tree_head_statement", "tree_head_dsse"),
    )
    second = _exact(
        comparison["second"],
        "second compared head",
        ("tree_head_statement", "tree_head_dsse"),
    )
    expected = _head_comparison_value(
        comparison["registry_config"],
        first["tree_head_statement"],
        first["tree_head_dsse"],
        second["tree_head_statement"],
        second["tree_head_dsse"],
        public_key_pem=public_key_pem,
    )
    if comparison != expected:
        raise ValueError("revocation registry head comparison does not independently recompute")
    return dict(comparison)


def _validate_inclusion_proof(value: Any, *, public_key_pem: bytes) -> Dict[str, Any]:
    proof = _exact(
        value,
        "revocation registry inclusion proof",
        (
            "schema",
            "schema_version",
            "registry_config",
            "tree_size",
            "leaf_index",
            "sequence",
            "entry",
            "entry_sha256",
            "leaf_sha256",
            "inclusion_path_sha256",
            "root_sha256",
            "tree_head_statement",
            "tree_head_dsse",
            "limitations",
            "interpretation_boundary",
        ),
    )
    if proof["schema"] != INCLUSION_PROOF_SCHEMA or proof["schema_version"] != 1:
        raise ValueError("unsupported LureRevoke registry inclusion-proof schema")
    config = _validate_config(proof["registry_config"])
    config_raw = _canonical(config)
    if config["signer_key_id"] != public_key_id(public_key_pem):
        raise ValueError("inclusion proof public key differs from its configured signer")
    tree_size = _integer(proof["tree_size"], "proof.tree_size", 1, MAX_ENTRIES)
    leaf_index = _integer(proof["leaf_index"], "proof.leaf_index", 0, MAX_ENTRIES - 1)
    sequence = _integer(proof["sequence"], "proof.sequence", 1, MAX_ENTRIES)
    if leaf_index >= tree_size or sequence != leaf_index + 1:
        raise ValueError("inclusion proof sequence and leaf index do not reconcile")
    entry = _validate_entry(proof["entry"], config=config, sequence=sequence)
    entry_raw = _canonical(entry)
    _digest(proof["entry_sha256"], "proof.entry_sha256")
    if proof["entry_sha256"] != _sha256(entry_raw):
        raise ValueError("inclusion proof entry digest does not recompute")
    leaf_hash = _leaf_hash(entry_raw)
    _digest(proof["leaf_sha256"], "proof.leaf_sha256")
    if proof["leaf_sha256"] != leaf_hash.hex():
        raise ValueError("inclusion proof leaf digest does not recompute")
    path_values = proof["inclusion_path_sha256"]
    if not isinstance(path_values, list) or len(path_values) > 64:
        raise ValueError("inclusion proof path must be a bounded list")
    path: list[bytes] = []
    for index, value_hash in enumerate(path_values):
        _digest(value_hash, f"proof.inclusion_path_sha256[{index}]")
        path.append(bytes.fromhex(value_hash))
    _digest(proof["root_sha256"], "proof.root_sha256")
    computed_root = _verify_inclusion_path(
        leaf_hash,
        leaf_index=leaf_index,
        tree_size=tree_size,
        inclusion_path=path,
    ).hex()
    if computed_root != proof["root_sha256"]:
        raise ValueError("inclusion proof path does not recompute its root")
    statement = _validate_tree_head(
        proof["tree_head_statement"],
        config=config,
        config_raw=config_raw,
        tree_size=tree_size,
        root_sha256=computed_root,
    )
    if sequence == tree_size and statement["predicate"]["latest_entry_sha256"] != _sha256(
        entry_raw
    ):
        raise ValueError("latest inclusion proof entry differs from the signed tree-head subject")
    statement_raw = _canonical(statement)
    envelope = proof["tree_head_dsse"]
    if not isinstance(envelope, dict):
        raise ValueError("inclusion proof tree-head DSSE must be an object")
    _verify_envelope(envelope, statement_raw, public_key_pem)
    if proof["limitations"] != INCLUSION_PROOF_LIMITATIONS:
        raise ValueError("inclusion proof limitations are invalid")
    if proof["interpretation_boundary"] != INCLUSION_PROOF_INTERPRETATION:
        raise ValueError("inclusion proof interpretation boundary is invalid")
    return dict(proof)


def _validate_consistency_proof(value: Any, *, public_key_pem: bytes) -> Dict[str, Any]:
    proof = _exact(
        value,
        "revocation registry consistency proof",
        (
            "schema",
            "schema_version",
            "registry_config",
            "first_tree_size",
            "first_root_sha256",
            "second_tree_size",
            "second_root_sha256",
            "consistency_path_sha256",
            "first_tree_head_statement",
            "first_tree_head_dsse",
            "second_tree_head_statement",
            "second_tree_head_dsse",
            "limitations",
            "interpretation_boundary",
        ),
    )
    if proof["schema"] != CONSISTENCY_PROOF_SCHEMA or proof["schema_version"] != 1:
        raise ValueError("unsupported LureRevoke registry consistency-proof schema")
    config = _validate_config(proof["registry_config"])
    config_raw = _canonical(config)
    if config["signer_key_id"] != public_key_id(public_key_pem):
        raise ValueError("consistency proof public key differs from its configured signer")
    first_size = _integer(proof["first_tree_size"], "proof.first_tree_size", 1, MAX_ENTRIES)
    second_size = _integer(proof["second_tree_size"], "proof.second_tree_size", 1, MAX_ENTRIES)
    if first_size >= second_size:
        raise ValueError("consistency proof requires a strictly larger second tree")
    _digest(proof["first_root_sha256"], "proof.first_root_sha256")
    _digest(proof["second_root_sha256"], "proof.second_root_sha256")
    path_values = proof["consistency_path_sha256"]
    if not isinstance(path_values, list) or not path_values or len(path_values) > 64:
        raise ValueError("consistency proof path must be a nonempty bounded list")
    path: list[bytes] = []
    for index, value_hash in enumerate(path_values):
        _digest(value_hash, f"proof.consistency_path_sha256[{index}]")
        path.append(bytes.fromhex(value_hash))
    _verify_consistency_path(
        bytes.fromhex(proof["first_root_sha256"]),
        bytes.fromhex(proof["second_root_sha256"]),
        first_size=first_size,
        second_size=second_size,
        consistency_path=path,
    )
    first_statement = _validate_tree_head(
        proof["first_tree_head_statement"],
        config=config,
        config_raw=config_raw,
        tree_size=first_size,
        root_sha256=proof["first_root_sha256"],
    )
    second_statement = _validate_tree_head(
        proof["second_tree_head_statement"],
        config=config,
        config_raw=config_raw,
        tree_size=second_size,
        root_sha256=proof["second_root_sha256"],
    )
    first_statement_raw = _canonical(first_statement)
    second_statement_raw = _canonical(second_statement)
    for label, envelope, statement_raw in (
        ("first", proof["first_tree_head_dsse"], first_statement_raw),
        ("second", proof["second_tree_head_dsse"], second_statement_raw),
    ):
        if not isinstance(envelope, dict):
            raise ValueError(f"{label} consistency-proof DSSE must be an object")
        _verify_envelope(envelope, statement_raw, public_key_pem)
    first_registered = _time(first_statement["predicate"]["registered_at"])
    second_registered = _time(second_statement["predicate"]["registered_at"])
    if second_registered < first_registered:
        raise ValueError("consistency proof second tree head predates the first")
    if first_size + 1 == second_size and second_statement["predicate"][
        "previous_tree_head_sha256"
    ] != _sha256(first_statement_raw):
        raise ValueError("adjacent consistency-proof tree heads do not chain directly")
    if proof["limitations"] != CONSISTENCY_PROOF_LIMITATIONS:
        raise ValueError("consistency proof limitations are invalid")
    if proof["interpretation_boundary"] != CONSISTENCY_PROOF_INTERPRETATION:
        raise ValueError("consistency proof interpretation boundary is invalid")
    return dict(proof)


def create_revocation_registry(
    output: Path,
    *,
    registry_id: str,
    system_id: str,
    environment: str,
    receiver_name: str,
    signer_public_key_pem: bytes,
    created_at: Optional[str] = None,
) -> Dict[str, Any]:
    target = Path(output)
    if target.exists() or target.is_symlink():
        raise FileExistsError(f"{target} already exists")
    config = _validate_config(
        {
            "schema": REGISTRY_SCHEMA,
            "schema_version": 1,
            "registry_id": registry_id,
            "created_at": created_at or _timestamp_now(),
            "producer": {"name": "lurescope", "version": __version__},
            "registration_policy": {
                "system_id": system_id,
                "environment": environment,
                "receiver_name": receiver_name,
                "require_authenticated_bundle": True,
            },
            "hash_profile": HASH_PROFILE,
            "signer_key_id": public_key_id(signer_public_key_pem),
            "limitations": list(LIMITATIONS),
            "interpretation_boundary": INTERPRETATION,
        }
    )
    target.mkdir(mode=0o700)
    try:
        (target / ENTRIES_DIRECTORY).mkdir(mode=0o700)
        _write_new(target / CONFIG_FILE, _canonical(config))
    except Exception:
        entries = target / ENTRIES_DIRECTORY
        if entries.is_dir():
            entries.rmdir()
        target.rmdir()
        raise
    return config


def _verify_state(
    registry: Path,
    *,
    public_key_pem: bytes,
    trusted_head_statement: Optional[Path] = None,
    trusted_head_dsse: Optional[Path] = None,
) -> Dict[str, Any]:
    root = _private_directory(Path(registry), "revocation registry")
    if {item.name for item in root.iterdir()} != {CONFIG_FILE, ENTRIES_DIRECTORY}:
        raise ValueError("revocation registry contains unexpected artifacts")
    config_raw = _read(root / CONFIG_FILE, private=True)
    config = _validate_config(_strict(config_raw, CONFIG_FILE))
    if config_raw != _canonical(config):
        raise ValueError("revocation registry config must use canonical JSON")
    if config["signer_key_id"] != public_key_id(public_key_pem):
        raise ValueError("registry public key differs from its configured signer")
    entries_root = _private_directory(root / ENTRIES_DIRECTORY, "registry entries directory")
    names = sorted(item.name for item in entries_root.iterdir())
    expected_names = [f"{sequence:08d}" for sequence in range(1, len(names) + 1)]
    if names != expected_names or len(names) > MAX_ENTRIES:
        raise ValueError("registry entry directories must be contiguous and bounded")

    frontier: list[Optional[bytes]] = []
    previous_entry_sha256 = None
    previous_tree_head_sha256 = None
    prior_evaluation_time = None
    seen_manifests: set[str] = set()
    seen_checkpoints: set[str] = set()
    seen_runs: set[str] = set()
    entry_raws: list[bytes] = []
    statement_raws: list[bytes] = []
    envelope_raws: list[bytes] = []
    for sequence, name in enumerate(names, start=1):
        directory = _private_directory(entries_root / name, f"registry entry {name}")
        if {item.name for item in directory.iterdir()} != {
            ENTRY_FILE,
            STATEMENT_FILE,
            DSSE_FILE,
        }:
            raise ValueError(f"registry entry {name} is incomplete or unexpected")
        entry_raw = _read(directory / ENTRY_FILE, private=True)
        entry = _validate_entry(
            _strict(entry_raw, f"{name}/{ENTRY_FILE}"), config=config, sequence=sequence
        )
        if entry_raw != _canonical(entry):
            raise ValueError("registry entries must use canonical JSON")
        if entry["previous_entry_sha256"] != previous_entry_sha256:
            raise ValueError("registry entry hash chain does not reconcile")
        evaluation_time = _time(entry["evidence"]["evaluation_generated_at"])
        if prior_evaluation_time is not None and evaluation_time <= prior_evaluation_time:
            raise ValueError("registry evaluation time must increase strictly")
        if _time(entry["registered_at"]) < evaluation_time:
            raise ValueError("registry entry cannot predate its evaluation")
        evidence = entry["evidence"]
        for value, seen, label in (
            (evidence["manifest_sha256"], seen_manifests, "manifest"),
            (evidence["checkpoint_sha256"], seen_checkpoints, "checkpoint"),
            (evidence["run_sha256"], seen_runs, "run"),
        ):
            if value in seen:
                raise ValueError(f"registry rejects replayed {label} evidence")
            seen.add(value)
        _frontier_add(frontier, _leaf_hash(entry_raw))
        expected_statement = _tree_head(
            config,
            config_raw,
            entry,
            entry_raw,
            _frontier_root(frontier).hex(),
            previous_tree_head_sha256,
        )
        statement_raw = _read(directory / STATEMENT_FILE, private=True)
        statement = _strict(statement_raw, f"{name}/{STATEMENT_FILE}")
        if statement != expected_statement or statement_raw != _canonical(expected_statement):
            raise ValueError("registry tree head does not independently recompute")
        envelope_raw = _read(directory / DSSE_FILE, private=True)
        envelope = _strict(envelope_raw, f"{name}/{DSSE_FILE}")
        if envelope_raw != _canonical(envelope):
            raise ValueError("registry tree-head DSSE must use canonical JSON")
        _verify_envelope(envelope, statement_raw, public_key_pem)
        entry_raws.append(entry_raw)
        statement_raws.append(statement_raw)
        envelope_raws.append(envelope_raw)
        previous_entry_sha256 = _sha256(entry_raw)
        previous_tree_head_sha256 = _sha256(statement_raw)
        prior_evaluation_time = evaluation_time

    if (trusted_head_statement is None) != (trusted_head_dsse is None):
        raise ValueError("trusted tree head requires both statement and DSSE files")
    trusted_size = None
    if trusted_head_statement is not None and trusted_head_dsse is not None:
        trusted_statement_raw = _read(Path(trusted_head_statement), private=True)
        trusted_statement = _strict(trusted_statement_raw, "trusted tree-head statement")
        predicate = (
            trusted_statement.get("predicate") if isinstance(trusted_statement, dict) else None
        )
        if not isinstance(predicate, dict) or predicate.get("registry_id") != config["registry_id"]:
            raise ValueError("trusted tree head names a different registry")
        trusted_size = _integer(predicate.get("tree_size"), "trusted tree size", 1, MAX_ENTRIES)
        if trusted_size > len(statement_raws):
            raise ValueError("registry is shorter than the externally retained tree head")
        if trusted_statement_raw != statement_raws[trusted_size - 1]:
            raise ValueError("registry conflicts with the externally retained tree head")
        trusted_envelope_raw = _read(Path(trusted_head_dsse), private=True)
        trusted_envelope = _strict(trusted_envelope_raw, "trusted tree-head DSSE")
        if trusted_envelope_raw != _canonical(trusted_envelope):
            raise ValueError("trusted tree-head DSSE must use canonical JSON")
        _verify_envelope(trusted_envelope, trusted_statement_raw, public_key_pem)

    return {
        "config": config,
        "config_raw": config_raw,
        "tree_size": len(entry_raws),
        "root_sha256": _frontier_root(frontier).hex(),
        "latest_entry_sha256": previous_entry_sha256,
        "latest_tree_head_sha256": previous_tree_head_sha256,
        "trusted_tree_size": trusted_size,
        "entry_raws": entry_raws,
        "statement_raws": statement_raws,
        "envelope_raws": envelope_raws,
    }


def verify_revocation_registry(
    registry: Path,
    *,
    public_key_pem: bytes,
    trusted_head_statement: Optional[Path] = None,
    trusted_head_dsse: Optional[Path] = None,
) -> Dict[str, Any]:
    state = _verify_state(
        registry,
        public_key_pem=public_key_pem,
        trusted_head_statement=trusted_head_statement,
        trusted_head_dsse=trusted_head_dsse,
    )
    return {
        "valid": True,
        "registry_id": state["config"]["registry_id"],
        "tree_size": state["tree_size"],
        "root_sha256": state["root_sha256"],
        "latest_entry_sha256": state["latest_entry_sha256"],
        "latest_tree_head_sha256": state["latest_tree_head_sha256"],
        "authenticated": state["tree_size"] > 0,
        "trusted_tree_size": state["trusted_tree_size"],
        "limitations": list(LIMITATIONS),
        "interpretation_boundary": INTERPRETATION,
    }


def create_revocation_inclusion_proof(
    registry: Path,
    output: Path,
    *,
    sequence: int,
    public_key_pem: bytes,
    tree_size: Optional[int] = None,
) -> Dict[str, Any]:
    """Export one entry with its shortest RFC 9162 Merkle inclusion path."""
    state = _verify_state(registry, public_key_pem=public_key_pem)
    available_size = state["tree_size"]
    selected_size = available_size if tree_size is None else tree_size
    _integer(selected_size, "inclusion proof tree size", 1, MAX_ENTRIES)
    _integer(sequence, "inclusion proof sequence", 1, MAX_ENTRIES)
    if selected_size > available_size:
        raise ValueError("inclusion proof tree size exceeds the available registry")
    if sequence > selected_size:
        raise ValueError("inclusion proof sequence is outside the selected tree head")
    entry_raws = state["entry_raws"][:selected_size]
    entry_raw = entry_raws[sequence - 1]
    entry = _strict(entry_raw, "inclusion proof entry")
    statement = _strict(
        state["statement_raws"][selected_size - 1],
        "inclusion proof tree-head statement",
    )
    envelope = _strict(
        state["envelope_raws"][selected_size - 1],
        "inclusion proof tree-head DSSE",
    )
    path = _inclusion_path(sequence - 1, entry_raws)
    proof = {
        "schema": INCLUSION_PROOF_SCHEMA,
        "schema_version": 1,
        "registry_config": state["config"],
        "tree_size": selected_size,
        "leaf_index": sequence - 1,
        "sequence": sequence,
        "entry": entry,
        "entry_sha256": _sha256(entry_raw),
        "leaf_sha256": _leaf_hash(entry_raw).hex(),
        "inclusion_path_sha256": [item.hex() for item in path],
        "root_sha256": _merkle_root(entry_raws).hex(),
        "tree_head_statement": statement,
        "tree_head_dsse": envelope,
        "limitations": list(INCLUSION_PROOF_LIMITATIONS),
        "interpretation_boundary": INCLUSION_PROOF_INTERPRETATION,
    }
    validated = _validate_inclusion_proof(proof, public_key_pem=public_key_pem)
    _write_new(Path(output), _canonical(validated))
    return validated


def verify_revocation_inclusion_proof(
    proof: Path,
    *,
    public_key_pem: bytes,
) -> Dict[str, Any]:
    raw = _read(Path(proof), private=True)
    value = _validate_inclusion_proof(
        _strict(raw, "revocation registry inclusion proof"),
        public_key_pem=public_key_pem,
    )
    if raw != _canonical(value):
        raise ValueError("revocation registry inclusion proof must use canonical JSON")
    return {
        "valid": True,
        "authenticated": True,
        "registry_id": value["registry_config"]["registry_id"],
        "tree_size": value["tree_size"],
        "leaf_index": value["leaf_index"],
        "sequence": value["sequence"],
        "entry_sha256": value["entry_sha256"],
        "root_sha256": value["root_sha256"],
        "signer_key_id": value["registry_config"]["signer_key_id"],
        "limitations": list(INCLUSION_PROOF_LIMITATIONS),
        "interpretation_boundary": INCLUSION_PROOF_INTERPRETATION,
    }


def create_revocation_consistency_proof(
    registry: Path,
    output: Path,
    *,
    first_tree_size: int,
    public_key_pem: bytes,
    second_tree_size: Optional[int] = None,
) -> Dict[str, Any]:
    """Export an RFC 9162 proof that two authenticated heads are prefix-consistent."""
    state = _verify_state(registry, public_key_pem=public_key_pem)
    available_size = state["tree_size"]
    selected_second = available_size if second_tree_size is None else second_tree_size
    _integer(first_tree_size, "first consistency-proof tree size", 1, MAX_ENTRIES)
    _integer(selected_second, "second consistency-proof tree size", 1, MAX_ENTRIES)
    if selected_second > available_size:
        raise ValueError("second consistency-proof tree size exceeds the available registry")
    if first_tree_size >= selected_second:
        raise ValueError("consistency proof requires a strictly larger second tree")
    entry_raws = state["entry_raws"][:selected_second]
    first_statement = _strict(
        state["statement_raws"][first_tree_size - 1],
        "first consistency-proof tree-head statement",
    )
    second_statement = _strict(
        state["statement_raws"][selected_second - 1],
        "second consistency-proof tree-head statement",
    )
    first_envelope = _strict(
        state["envelope_raws"][first_tree_size - 1],
        "first consistency-proof tree-head DSSE",
    )
    second_envelope = _strict(
        state["envelope_raws"][selected_second - 1],
        "second consistency-proof tree-head DSSE",
    )
    proof = {
        "schema": CONSISTENCY_PROOF_SCHEMA,
        "schema_version": 1,
        "registry_config": state["config"],
        "first_tree_size": first_tree_size,
        "first_root_sha256": _merkle_root(entry_raws[:first_tree_size]).hex(),
        "second_tree_size": selected_second,
        "second_root_sha256": _merkle_root(entry_raws).hex(),
        "consistency_path_sha256": [
            item.hex() for item in _consistency_path(first_tree_size, entry_raws)
        ],
        "first_tree_head_statement": first_statement,
        "first_tree_head_dsse": first_envelope,
        "second_tree_head_statement": second_statement,
        "second_tree_head_dsse": second_envelope,
        "limitations": list(CONSISTENCY_PROOF_LIMITATIONS),
        "interpretation_boundary": CONSISTENCY_PROOF_INTERPRETATION,
    }
    validated = _validate_consistency_proof(proof, public_key_pem=public_key_pem)
    _write_new(Path(output), _canonical(validated))
    return validated


def verify_revocation_consistency_proof(
    proof: Path,
    *,
    public_key_pem: bytes,
) -> Dict[str, Any]:
    raw = _read(Path(proof), private=True)
    value = _validate_consistency_proof(
        _strict(raw, "revocation registry consistency proof"),
        public_key_pem=public_key_pem,
    )
    if raw != _canonical(value):
        raise ValueError("revocation registry consistency proof must use canonical JSON")
    return {
        "valid": True,
        "authenticated": True,
        "registry_id": value["registry_config"]["registry_id"],
        "first_tree_size": value["first_tree_size"],
        "first_root_sha256": value["first_root_sha256"],
        "second_tree_size": value["second_tree_size"],
        "second_root_sha256": value["second_root_sha256"],
        "signer_key_id": value["registry_config"]["signer_key_id"],
        "limitations": list(CONSISTENCY_PROOF_LIMITATIONS),
        "interpretation_boundary": CONSISTENCY_PROOF_INTERPRETATION,
    }


def compare_revocation_tree_heads(
    registry_config: Path,
    first_statement: Path,
    first_dsse: Path,
    second_statement: Path,
    second_dsse: Path,
    output: Path,
    *,
    public_key_pem: bytes,
) -> Dict[str, Any]:
    config_raw = _read(Path(registry_config), private=True)
    config = _validate_config(_strict(config_raw, "registry config"))
    if config_raw != _canonical(config):
        raise ValueError("registry config must use canonical JSON")

    def artifact(path: Path, label: str) -> Dict[str, Any]:
        raw = _read(Path(path), private=True)
        value = _strict(raw, label)
        if not isinstance(value, dict) or raw != _canonical(value):
            raise ValueError(f"{label} must be a canonical JSON object")
        return dict(value)

    comparison = _head_comparison_value(
        config,
        artifact(first_statement, "first tree-head statement"),
        artifact(first_dsse, "first tree-head DSSE"),
        artifact(second_statement, "second tree-head statement"),
        artifact(second_dsse, "second tree-head DSSE"),
        public_key_pem=public_key_pem,
    )
    _write_new(Path(output), _canonical(comparison))
    return comparison


def verify_revocation_head_comparison(
    comparison: Path,
    *,
    public_key_pem: bytes,
) -> Dict[str, Any]:
    raw = _read(Path(comparison), private=True)
    value = _validate_head_comparison(
        _strict(raw, "revocation registry head comparison"),
        public_key_pem=public_key_pem,
    )
    if raw != _canonical(value):
        raise ValueError("revocation registry head comparison must use canonical JSON")
    return {
        "valid": True,
        "authenticated": True,
        "registry_id": value["registry_config"]["registry_id"],
        "summary": value["summary"],
        "signer_key_id": value["registry_config"]["signer_key_id"],
        "limitations": list(HEAD_COMPARISON_LIMITATIONS),
        "interpretation_boundary": HEAD_COMPARISON_INTERPRETATION,
    }


def append_revocation_registry(
    registry: Path,
    bundle: Path,
    *,
    registry_public_key_pem: bytes,
    registry_signing_key_pem: bytes,
    bundle_public_key_pem: bytes,
    registered_at: Optional[str] = None,
) -> Dict[str, Any]:
    state = _verify_state(registry, public_key_pem=registry_public_key_pem)
    if state["tree_size"] >= MAX_ENTRIES:
        raise ValueError("revocation registry reached its maximum entry count")
    key = _private_key(registry_signing_key_pem)
    if not secrets.compare_digest(_private_key_id(key), state["config"]["signer_key_id"]):
        raise ValueError("registry signing key does not match its configured public key")
    verified = verify_revocation_bundle(Path(bundle), public_key_pem=bundle_public_key_pem)
    if not verified["authenticated"] or len(verified["key_ids"]) != 1:
        raise ValueError("registry accepts only authenticated LureRevoke bundles")
    report = verified["report"]
    run = report["run"]
    policy = state["config"]["registration_policy"]
    if (
        verified["system_id"] != policy["system_id"]
        or verified["environment"] != policy["environment"]
        or run["implementation"]["name"] != policy["receiver_name"]
    ):
        raise ValueError("revocation bundle violates the registry registration policy")
    created = registered_at or _timestamp_now()
    _timestamp(created, "entry.registered_at")
    if _time(created) < _time(report["generated_at"]):
        raise ValueError("registry entry cannot predate its evaluation")
    sequence = state["tree_size"] + 1
    entry = _validate_entry(
        {
            "schema": ENTRY_SCHEMA,
            "schema_version": 1,
            "registry_id": state["config"]["registry_id"],
            "sequence": sequence,
            "registered_at": created,
            "previous_entry_sha256": state["latest_entry_sha256"],
            "system": {
                "system_id": verified["system_id"],
                "environment": verified["environment"],
            },
            "receiver": {
                "name": run["implementation"]["name"],
                "version": run["implementation"]["version"],
                "artifact_sha256": run["implementation"]["artifact_sha256"],
                "bundle_signer_key_id": verified["key_ids"][0],
            },
            "evidence": {
                "manifest_sha256": verified["manifest_sha256"],
                "checkpoint_sha256": verified["statement_sha256"],
                "plan_sha256": report["plan_sha256"],
                "run_sha256": report["run_sha256"],
                "evaluation_generated_at": report["generated_at"],
                "overall_status": verified["overall_status"],
            },
            "privacy": {
                "contains_revocation_evaluation": False,
                "contains_subject_or_event_identifiers": False,
                "contains_tokens_credentials_prompts_payloads_or_targets": False,
            },
            "limitations": list(LIMITATIONS),
        },
        config=state["config"],
        sequence=sequence,
    )
    evidence = entry["evidence"]
    existing = [_strict(raw, "existing registry entry") for raw in state["entry_raws"]]
    for field in ("manifest_sha256", "checkpoint_sha256", "run_sha256"):
        if evidence[field] in {item["evidence"][field] for item in existing}:
            raise ValueError(f"registry rejects replayed {field.removesuffix('_sha256')}")
    if existing and _time(evidence["evaluation_generated_at"]) <= _time(
        existing[-1]["evidence"]["evaluation_generated_at"]
    ):
        raise ValueError("registry requires strictly newer evaluation evidence")

    entry_raw = _canonical(entry)
    frontier: list[Optional[bytes]] = []
    for raw in [*state["entry_raws"], entry_raw]:
        _frontier_add(frontier, _leaf_hash(raw))
    statement = _tree_head(
        state["config"],
        state["config_raw"],
        entry,
        entry_raw,
        _frontier_root(frontier).hex(),
        state["latest_tree_head_sha256"],
    )
    statement_raw = _canonical(statement)
    envelope_raw = _canonical(_sign_statement(statement_raw, key))
    _verify_envelope(
        _strict(envelope_raw, "new tree-head DSSE"),
        statement_raw,
        registry_public_key_pem,
    )

    registry_root = Path(registry)
    entries_root = registry_root / ENTRIES_DIRECTORY
    target = entries_root / f"{sequence:08d}"
    # Stage beside—not inside—the committed registry. If the process is killed
    # before rename, an orphan cannot make the strict entries namespace invalid.
    staging = registry_root.parent / (
        f".{registry_root.name}.pending-append-{secrets.token_hex(12)}"
    )
    staging.mkdir(mode=0o700)
    try:
        _write_new(staging / ENTRY_FILE, entry_raw)
        _write_new(staging / STATEMENT_FILE, statement_raw)
        _write_new(staging / DSSE_FILE, envelope_raw)
        staging_descriptor = os.open(staging, os.O_RDONLY)
        try:
            os.fsync(staging_descriptor)
        finally:
            os.close(staging_descriptor)
        os.rename(staging, target)
        descriptor = os.open(entries_root, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except Exception:
        if staging.is_dir():
            for item in staging.iterdir():
                item.unlink()
            staging.rmdir()
        raise
    return verify_revocation_registry(registry, public_key_pem=registry_public_key_pem)
