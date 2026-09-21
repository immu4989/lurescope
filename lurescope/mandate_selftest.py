"""Offline diagnostics for the authority evidence shipped in this installation."""

from __future__ import annotations

import copy
import hashlib
import importlib
import importlib.metadata
from pathlib import Path
from typing import Any, Dict, Optional

from . import __version__
from .mandate import _read
from .permit import _strict

REFERENCE_CASES = (
    ("authority", "mandate", "validate_mandate_verification", "luremandate-v1/verification.json"),
    (
        "signed-approvals",
        "mandate_auth",
        "validate_authenticated_mandate_verification",
        "luremandate-v1/authenticated-verification.json",
    ),
    (
        "telemetry",
        "mandate_otel",
        "validate_mandate_otel_projection",
        "luremandate-v1/otel-projection.json",
    ),
    (
        "signed-telemetry",
        "mandate_otel_auth",
        "validate_authenticated_mandate_otel_projection",
        "luremandate-v1/authenticated-otel-projection.json",
    ),
    (
        "gateway-score",
        "mandate_conformance",
        "validate_mandate_conformance_verification",
        "luremandate-v1/conformance-verification.json",
    ),
    (
        "signed-gateway-score",
        "mandate_conformance_auth",
        "validate_authenticated_mandate_conformance_verification",
        "luremandate-v1/authenticated-conformance-verification.json",
    ),
    (
        "pairwise",
        "mandate_pairwise",
        "validate_pairwise_mandate_verification",
        "luremandate-pairwise-v1/pairwise-verification.json",
    ),
    (
        "counterfactual",
        "mandate_counterfactual",
        "validate_counterfactual_mandate_verification",
        "luremandate-counterfactual-v1/counterfactual-verification.json",
    ),
    (
        "sequence",
        "mandate_sequence",
        "validate_sequence_mandate_verification",
        "luremandate-sequence-v1/sequence-verification.json",
    ),
    (
        "shared-state",
        "mandate_conformance",
        "validate_mandate_conformance_verification",
        "luremandate-transitions-v1/verification.json",
    ),
)


def reference_corpus_root() -> Path:
    """Locate either source fixtures or installed data-files through wheel metadata."""
    checkout = Path(__file__).resolve().parents[1]
    if (checkout / "pyproject.toml").is_file() and (checkout / "conformance").is_dir():
        return checkout / "conformance"
    suffix = "share/lurescope/conformance/luremandate-v1/verification.json"
    try:
        distribution = importlib.metadata.distribution("lurescope")
    except importlib.metadata.PackageNotFoundError as exc:
        raise FileNotFoundError("LureScope installation metadata is unavailable") from exc
    for item in distribution.files or ():
        if str(item).replace("\\", "/").endswith(suffix):
            return Path(distribution.locate_file(item)).resolve().parents[1]
    raise FileNotFoundError("installed LureScope authority reference corpus is unavailable")


def _rejection_probes(value: Dict[str, Any], validator: Any) -> Dict[str, bool]:
    """Exercise parser and recomputation failure paths without changing fixtures."""
    probes = {}
    for name in ("boolean-version", "float-version", "unknown-field", "derived-claim"):
        mutated = copy.deepcopy(value)
        if name == "boolean-version":
            mutated["schema_version"] = True
        elif name == "float-version":
            mutated["schema_version"] = 1.0
        elif name == "unknown-field":
            mutated["selftest_unrecognized_field"] = True
        elif "summary" in mutated:
            mutated["summary"]["verdict"] = "fail"
        else:
            digest = mutated["run_sha256"]
            mutated["run_sha256"] = ("1" if digest[0] == "0" else "0") + digest[1:]
        try:
            validator(mutated)
        except ValueError:
            probes[name] = True
        else:
            probes[name] = False
    return probes


def run_mandate_selftest(corpus_root: Optional[Path] = None) -> Dict[str, Any]:
    """Validate bundled examples; this does not test any deployed gateway."""
    root = Path(corpus_root) if corpus_root is not None else reference_corpus_root()
    results = []
    for name, module_name, validator_name, relative in REFERENCE_CASES:
        record: Dict[str, Any] = {"profile": name, "artifact": relative, "status": "error"}
        try:
            path = root / relative
            module = importlib.import_module(f"lurescope.{module_name}")
            payload = _read(path, "reference artifact", 32 * 1024 * 1024)
            value = _strict(payload, "reference artifact")
            validator = getattr(module, validator_name)
            result = validator(value)
            if module_name == "mandate_otel":
                passed = len(result["run"]["transactions"]) == 16
            else:
                passed = result.get("summary", {}).get("verdict") == "pass"
            probes = _rejection_probes(value, validator)
            record["rejection_probes"] = probes
            record["status"] = "pass" if passed and all(probes.values()) else "fail"
            record["artifact_sha256"] = hashlib.sha256(payload).hexdigest()
        except (OSError, ValueError, ImportError, KeyError, TypeError) as exc:
            record["error_type"] = type(exc).__name__
        results.append(record)
    passed = sum(item["status"] == "pass" for item in results)
    return {
        "kind": "lurescope-mandate-reference-selftest",
        "package_version": __version__,
        "reference_only": True,
        "summary": {
            "status": "pass" if passed == len(results) else "fail",
            "passed": passed,
            "total": len(results),
        },
        "results": results,
        "boundary": "Checks packaged reference evidence; no deployed gateway is tested.",
    }
