"""Check data-only default scoring from a trusted local wheel, outside checkout.

Run in a fresh interpreter after installing the wheel with --no-deps --target.
No providers, downloads, model deserialization, or production traffic are used.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib
import math
import os
import sys
import tempfile
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch


class ForbidModelFrameworks:
    def find_spec(self, fullname, path=None, target=None):
        if fullname.split(".")[0] in {"pickle", "joblib", "sklearn", "numpy", "torch"}:
            raise ImportError("executable model framework forbidden in portable serving check")
        return None


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--installed-root", type=Path, required=True)
    args = parser.parse_args(argv)
    root = args.installed_root.resolve(strict=True)
    checkout = Path(__file__).resolve().parents[1]
    if Path.cwd().resolve().is_relative_to(checkout):
        parser.error("run outside the source checkout")
    forbidden = {"lurescope", "joblib", "pickle", "sklearn", "numpy", "torch"}
    if any(name.split(".")[0] in forbidden for name in sys.modules):
        parser.error("use a fresh interpreter without model frameworks")
    if not (root / "lurescope/__init__.py").is_file():
        parser.error("installed LureScope initializer is missing")
    sys.path.insert(0, str(root))
    sys.meta_path.insert(0, ForbidModelFrameworks())
    service = importlib.import_module("lurescope.service")
    policy_module = importlib.import_module("lurescope.policy")
    calibration = importlib.import_module("lurebench.calibration")
    portable = importlib.import_module("lurescope.portable_tfidf")
    with tempfile.TemporaryDirectory(prefix="lurescope-policy-check-") as directory:
        for objective in ("max_mcc", "target_fpr", "risk_controlled_fpr"):
            policy, _ = calibration.build_policy(
                "tfidf-logreg", "fraud", [str(i) for i in range(401)],
                [0] * 400 + [1], [.1] * 400 + [.9], objective, .01,
            )
            path = Path(directory) / f"{objective}.json"
            policy.save(str(path))
            loaded = policy_module.load_policy(str(path))
            status = policy_module.policy_status(loaded)
            if (loaded.policy_id != policy.policy_id or status["detector_binding"] != "name_only"
                    or status["detector_configuration_verified"] is not False):
                raise ValueError("installed policy lost evidence identity or binding limitation")
            binding = calibration.DetectorBinding(**portable.detector_binding(
                service._detector("tfidf-logreg"),
            ))
            bound, _ = calibration.build_policy(
                "tfidf-logreg", "fraud", [str(i) for i in range(401)],
                [0] * 400 + [1], [.1] * 400 + [.9], objective, .01, detector_binding=binding,
            )
            bound.save(str(path))
            loaded = policy_module.load_policy(str(path))
            if (loaded.schema_version != 3 or not service.policy_status_for_deployment(loaded)[
                    "detector_configuration_verified"]):
                raise ValueError("installed bound policy did not match actual detector")
            changed = replace(loaded, detector_binding=replace(
                loaded.detector_binding, runtime_sha256="f" * 64,
            ))
            try:
                service._check_policy_binding(changed, service._detector("tfidf-logreg"))
            except RuntimeError:
                pass
            else:
                raise ValueError("installed runtime mismatch was accepted")
        # The final loop artifact is an actual v3 risk-controlled policy.
        with patch.dict(os.environ, {
            "LURESCOPE_POLICY_PATH": str(path),
            "LURESCOPE_POLICY_SHA256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "LURESCOPE_POLICY_ENFORCEMENT": "risk_controlled_bound",
        }, clear=True):
            if not service.policy_readiness()["ready"]:
                raise ValueError("installed enforced policy was not ready")
            if service.score("Synthetic notes").policy_id != bound.policy_id:
                raise ValueError("installed scoring bypassed approved policy")
            for options in ({"threshold": .5}, {"detector_name": "heuristic-v0"},
                            {"engine": "ignored"}):
                try:
                    service.score("Synthetic notes", **options)
                except policy_module.PolicyRequestError:
                    pass
                else:
                    raise ValueError("installed enforcement accepted a client override")
            try:
                service.attack("Synthetic notes", "homoglyph")
            except policy_module.PolicyRequestError:
                pass
            else:
                raise ValueError("installed enforcement accepted exploration")
            os.environ.pop("LURESCOPE_POLICY_SHA256")
            if service.policy_readiness()["ready"]:
                raise ValueError("installed readiness ignored missing trust pin")
            try:
                service.score("Synthetic notes")
            except policy_module.PolicyRequirementError:
                pass
            else:
                raise ValueError("installed worker reused an unpinned policy")
    try:
        service.score("Synthetic input", detector_name="binoculars")
    except service.DetectorUnavailable:
        pass
    else:
        raise ValueError("installed fraud service accepted a provenance-only detector")
    detector = service._detector("tfidf-logreg")
    if not isinstance(detector, portable.PortableTfidfDetector):
        raise ValueError("default serving did not select the data-only model")
    for index in range(32):
        if service._detector("tfidf-logreg", f"unused-{index}", f"unused-{index}") is not detector:
            raise ValueError("ignored provider options multiplied installed local models")
    if len(service._LOCAL_DETECTORS) != 1:
        raise ValueError("installed detector cache retained unexpected entries")
    original_constructor = service.get_detector
    guard_env = ("LURESCOPE_ALLOW_UNSAFE_LLAMA_GUARD", "LURESCOPE_LLAMA_GUARD_REVISION")
    original_guard_env = {name: os.environ.get(name) for name in guard_env}
    try:
        service.get_detector = lambda *args, **kwargs: object()
        os.environ.pop(guard_env[0], None)
        try:
            service._detector("llama-guard-3")
        except service.DetectorUnavailable:
            pass
        else:
            raise ValueError("installed HTTP service allowed implicit optional model loading")
        os.environ[guard_env[0]] = "1"
        os.environ[guard_env[1]] = "a" * 40
        service._detector("llama-guard-3")  # Synthetic constructor only.
        os.environ.pop(guard_env[0])
        try:
            service._detector("llama-guard-3")
        except service.DetectorUnavailable:
            pass
        else:
            raise ValueError("installed warm model cache bypassed operator revocation")
        for name in ("llm-judge", "openai-moderation"):
            first = service._detector(name, "synthetic")
            if service._detector(name, "synthetic") is first:
                raise ValueError("installed service retained a provider detector")
        for name in ("unknown", "llm-judge-provenance"):
            try:
                service._detector(name)
            except KeyError:
                pass
            else:
                raise ValueError("installed service constructed an unserved detector")
    finally:
        service.get_detector = original_constructor
        for name, value in original_guard_env.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value
        service._detector.cache_clear()
    # Fixed historical-model anchor plus threshold and signal smoke checks.
    result = service.score("Please verify your bank account", threshold=.5)
    if (
        not math.isclose(result.fraud_probability, .8944714598915419, abs_tol=1e-12,
                         rel_tol=0.)
        or result.label != "fraud" or not result.signals
    ):
        raise ValueError("installed default scoring changed from its reviewed anchor")
    proof_module = importlib.import_module("lurescope.proof")
    statement = proof_module.create_email_proof(
        b"Subject: Team notes\n\nPlease review the project notes.",
        created_at="2026-10-02T00:00:00Z", subject_salt=bytes(range(32)),
    )
    if not proof_module.verify_proof(statement)["valid"]:
        raise ValueError("installed data-only proof failed verification")
    repeated = proof_module.create_email_proof(
        b"Subject: Notes\n\nLinks http://192.0.2.1/ and http://192.0.2.2/",
        created_at="2026-10-02T00:00:00Z", subject_salt=bytes(range(32)),
    )
    assessment = repeated["predicate"]["assessment"]
    if (not proof_module.verify_proof(repeated)["valid"]
            or assessment["evidence_codes"] != ["ip_literal_url"]
            or assessment["url_count"] != 2):
        raise ValueError("installed proof lost repeated findings or emitted duplicate categories")
    with tempfile.TemporaryDirectory(prefix="lurescope-proof-write-") as directory:
        output = Path(directory) / "proof.json"
        publication = proof_module.write_proof(output, repeated)
        before = output.read_bytes()
        if not publication["valid"] or proof_module.load_proof(output) != repeated:
            raise ValueError("installed proof publication changed the artifact")
        if os.name == "posix" and output.stat().st_mode & 0o077:
            raise ValueError("installed proof publication granted group/world access")
        try:
            proof_module.write_proof(output, statement)
        except FileExistsError:
            pass
        else:
            raise ValueError("installed proof publication replaced existing evidence")
        if output.read_bytes() != before or list(Path(directory).glob(".lureproof-*.tmp")):
            raise ValueError("installed proof publication changed evidence or leaked staging files")
    triage = importlib.import_module("lurescope.triage")
    nested = (b"Content-Type: message/rfc822\n\n" * 1200
              + b"Subject: Notes\n\nOrdinary notes")
    wide = (b"Content-Type: multipart/mixed; boundary=wide\n\n"
            + b"--wide\nContent-Type: text/plain\n\nNotes\n" * 256
            + b"--wide--\n")
    nested_header = (b"From: " + b"(" * 1200 + b"comment" + b")" * 1200
                     + b" <sender@example.test>\n\nNotes")
    oversized_header = b"X-Padding: " + b"x" * 16384 + b"\n\nNotes"
    for raw in (nested, wide, nested_header, oversized_header):
        try:
            proof_module.create_email_proof(raw)
        except triage.EmailTooComplex:
            pass
        else:
            raise ValueError("installed proof creation accepted over-complex email")
    for name, module in list(sys.modules.items()):
        if name == "lurescope" or name.startswith("lurescope."):
            location = getattr(module, "__file__", None)
            if location is None or not Path(location).resolve().is_relative_to(root):
                raise ValueError("LureScope import escaped the installed root")
    print("PASS installed data-only scoring, private proof publication, and MIME/header limits "
          "with model frameworks blocked")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
