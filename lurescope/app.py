"""LureScope API — score a message for fraud, and watch an attacker try to evade.

Run locally:

    uvicorn lurescope.app:app --reload

Then open http://127.0.0.1:8000 for the demo, or POST to /score and /attack.
"""

from __future__ import annotations

import os

from fastapi import Depends, FastAPI, HTTPException
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from . import __version__, service
from .http_boundary import RequestBodyLimit
from .models import (
    AttackRequest,
    AttackResponse,
    CapabilitiesResponse,
    DetectorInfo,
    EmailTriageRequest,
    EmailTriageResponse,
    LureProofRequest,
    LureProofVerifyRequest,
    LureProofVerifyResponse,
    PolicyStatusResponse,
    ScoreRequest,
    ScoreResponse,
    SecurityStatusResponse,
)
from .policy import configured_policy
from .proof import create_email_proof, verify_proof
from .security import enforce_request_policy, require_api_access, security_status
from .triage import EmailTooLarge, triage_email

_STATIC = os.path.join(os.path.dirname(__file__), "static")

app = FastAPI(
    title="LureScope",
    version=__version__,
    description=(
        "Score a message for fraud-lure likelihood, then stress-test the detector "
        "against attacks a real fraudster would run. Deployable companion to LureBench."
    ),
)
app.add_middleware(RequestBodyLimit)


@app.exception_handler(RequestValidationError)
async def invalid_request(_request, _exc):
    # Framework defaults can include raw field values or the submitted body.
    # Email/message content must not become diagnostic response material.
    return JSONResponse({"detail": "request validation failed"}, status_code=422)


@app.get("/health")
def health() -> dict:
    posture = security_status()
    if posture["mode"] == "misconfigured":
        raise HTTPException(503, "deployment security is misconfigured")
    return {"status": "ok", "version": __version__}


@app.get("/capabilities", response_model=CapabilitiesResponse)
def capabilities() -> CapabilitiesResponse:
    return CapabilitiesResponse(
        detectors=service.available_detectors(),
        detector_catalog=[DetectorInfo(**d) for d in service.detector_catalog()],
        attacks=service.available_attacks(),
        defenses=service.available_defenses_(),
        default_detector=service.DEFAULT_DETECTOR,
        workflows=["score", "attack", "email-triage", "lureproof", "risk-controlled-policy"],
    )


@app.get("/policy", response_model=PolicyStatusResponse)
def decision_policy() -> PolicyStatusResponse:
    """Expose non-secret policy provenance, assurance evidence, and limitations."""
    try:
        return PolicyStatusResponse(**service.policy_status_for_deployment(configured_policy()))
    except Exception as exc:  # noqa: BLE001 - private filesystem/model diagnostics
        raise HTTPException(503, "decision policy configuration is unavailable") from exc


@app.get("/security", response_model=SecurityStatusResponse)
def deployment_security() -> SecurityStatusResponse:
    """Expose deployment posture without revealing credentials or provider keys."""
    return SecurityStatusResponse(**security_status())


@app.get("/policy/readiness")
def decision_policy_readiness():
    """Readiness for operator-enforced scoring, not general service liveness."""
    result = service.policy_readiness()
    return JSONResponse(result, status_code=200 if result["ready"] else 503,
                        headers={"Cache-Control": "no-store"})


def _admit_policy_request(req, *, research=False):
    # This first gate precedes provider quota reservation. The Python service
    # independently gates again so direct callers cannot bypass admission.
    try:
        if research:
            service.require_research_mode()
        elif service.policy_enforcement() != "off":
            service.decision_policy_for_request(req.detector, req.threshold, req.engine, req.model)
    except service.PolicyRequestError as exc:
        raise HTTPException(403, "request is disabled by decision policy enforcement") from exc
    except service.PolicyRequirementError as exc:
        raise HTTPException(503, "required decision policy is unavailable") from exc


@app.post(
    "/score",
    response_model=ScoreResponse,
    dependencies=[Depends(require_api_access)],
)
def score(req: ScoreRequest) -> ScoreResponse:
    if req.detector not in service.all_detectors():
        raise HTTPException(400, f"unknown detector {req.detector!r}")
    _admit_policy_request(req)
    enforce_request_policy(detector=req.detector, engine=req.engine, model=req.model)
    try:
        r = service.score(
            req.text,
            detector_name=req.detector,
            threshold=req.threshold,
            engine=req.engine,
            model=req.model,
        )
    except service.PolicyRequestError as exc:
        raise HTTPException(403, "request is disabled by decision policy enforcement") from exc
    except service.PolicyRequirementError as exc:
        raise HTTPException(503, "required decision policy is unavailable") from exc
    except service.DetectorUnavailable as exc:  # detector needs a key/dep not configured
        raise HTTPException(400, service._needs(req.detector)) from exc
    except Exception as exc:  # noqa: BLE001 - provider/model failure at score time
        raise HTTPException(502, "score unavailable; no risk decision was produced") from exc
    return ScoreResponse(**r.__dict__)


@app.post(
    "/attack",
    response_model=AttackResponse,
    dependencies=[Depends(require_api_access)],
)
def attack(req: AttackRequest) -> AttackResponse:
    if req.detector not in service.all_detectors():
        raise HTTPException(400, f"unknown detector {req.detector!r}")
    if req.attack not in service.available_attacks():
        raise HTTPException(400, f"unknown attack {req.attack!r}")
    if req.defense not in service.available_defenses_():
        raise HTTPException(400, f"unknown defense {req.defense!r}")
    _admit_policy_request(req, research=True)
    enforce_request_policy(
        detector=req.detector,
        attack=req.attack,
        defense=req.defense,
        engine=req.engine,
        model=req.model,
    )
    try:
        r = service.attack(
            req.text,
            req.attack,
            detector_name=req.detector,
            threshold=req.threshold,
            engine=req.engine,
            model=req.model,
            defense=req.defense,
        )
    except service.PolicyRequestError as exc:
        raise HTTPException(403, "request is disabled by decision policy enforcement") from exc
    except service.PolicyRequirementError as exc:
        raise HTTPException(503, "required decision policy is unavailable") from exc
    except ValueError as exc:  # llm attack/detector without a configured provider
        raise HTTPException(
            400, "attack unavailable; check detector/provider configuration and input"
        ) from exc
    except Exception as exc:  # noqa: BLE001 - provider/model failure, keep it a 502
        raise HTTPException(
            502, "attack evaluation unavailable; no resilience result was produced"
        ) from exc
    return AttackResponse(**r.__dict__)


@app.post(
    "/triage/email",
    response_model=EmailTriageResponse,
    dependencies=[Depends(require_api_access)],
)
def triage_email_message(req: EmailTriageRequest) -> EmailTriageResponse:
    """Triage raw email locally without fetching links or opening attachments."""
    if req.detector not in service.all_detectors():
        raise HTTPException(400, f"unknown detector {req.detector!r}")
    _admit_policy_request(req)
    enforce_request_policy(detector=req.detector, engine=req.engine, model=req.model)
    try:
        result = triage_email(
            req.email_bytes(),
            detector_name=req.detector,
            threshold=req.threshold,
            engine=req.engine,
            model=req.model,
        )
    except service.PolicyRequestError as exc:
        raise HTTPException(403, "request is disabled by decision policy enforcement") from exc
    except service.PolicyRequirementError as exc:
        raise HTTPException(503, "required decision policy is unavailable") from exc
    except service.DetectorUnavailable as exc:
        raise HTTPException(400, service._needs(req.detector)) from exc
    except (EmailTooLarge, ValueError) as exc:
        raise HTTPException(400, "email triage rejected input or detector configuration") from exc
    except Exception as exc:  # noqa: BLE001 - provider failure at score time
        raise HTTPException(502, "email triage unavailable; no risk decision was produced") from exc
    return EmailTriageResponse(**result.as_dict())


@app.post("/proof/email", dependencies=[Depends(require_api_access)])
def prove_email_message(req: LureProofRequest) -> dict:
    """Create minimized unsigned evidence; issuer signing is an offline operation."""
    if req.detector not in service.all_detectors():
        raise HTTPException(400, f"unknown detector {req.detector!r}")
    _admit_policy_request(req, research=True)
    enforce_request_policy(detector=req.detector, engine=req.engine, model=req.model)
    try:
        return create_email_proof(
            req.email_bytes(),
            detector_name=req.detector,
            threshold=req.threshold,
            engine=req.engine,
            model=req.model,
            privacy_profile=req.privacy_profile,
            nonce=req.nonce,
        )
    except service.PolicyRequestError as exc:
        raise HTTPException(403, "request is disabled by decision policy enforcement") from exc
    except service.PolicyRequirementError as exc:
        raise HTTPException(503, "required decision policy is unavailable") from exc
    except service.DetectorUnavailable as exc:
        raise HTTPException(400, service._needs(req.detector)) from exc
    except (EmailTooLarge, ValueError) as exc:
        raise HTTPException(400, "proof creation rejected input or detector configuration") from exc
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(502, "proof creation unavailable; no proof was produced") from exc


@app.post(
    "/proof/verify",
    response_model=LureProofVerifyResponse,
    dependencies=[Depends(require_api_access)],
)
def verify_lureproof(req: LureProofVerifyRequest) -> LureProofVerifyResponse:
    public_key = req.public_key_pem.encode("utf-8") if req.public_key_pem else None
    result = verify_proof(req.proof, public_key, req.require_signature)
    if not result["valid"]:
        # Local verification retains detailed field diagnostics; the HTTP
        # endpoint must not echo arbitrary submitted property names or values.
        result["errors"] = ["proof validation failed"]
    return LureProofVerifyResponse(**result)


@app.get("/")
def index() -> FileResponse:
    return FileResponse(os.path.join(_STATIC, "index.html"), headers={"Cache-Control": "no-cache"})


class RevalidatingStaticFiles(StaticFiles):
    async def get_response(self, path, scope):
        response = await super().get_response(path, scope)
        response.headers["Cache-Control"] = "no-cache"
        return response


# Revalidate assets rather than pairing new HTML with a stale cached script.
app.mount("/static", RevalidatingStaticFiles(directory=_STATIC), name="static")
