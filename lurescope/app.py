"""LureScope API — score a message for fraud, and watch an attacker try to evade.

Run locally:

    uvicorn lurescope.app:app --reload

Then open http://127.0.0.1:8000 for the demo, or POST to /score and /attack.
"""

from __future__ import annotations

import os

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from . import __version__, service
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
)
from .policy import configured_policy, policy_status
from .proof import create_email_proof, verify_proof
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


@app.get("/health")
def health() -> dict:
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
    return PolicyStatusResponse(**policy_status(configured_policy()))


@app.post("/score", response_model=ScoreResponse)
def score(req: ScoreRequest) -> ScoreResponse:
    if req.detector not in service.all_detectors():
        raise HTTPException(400, f"unknown detector {req.detector!r}")
    try:
        r = service.score(
            req.text,
            detector_name=req.detector,
            threshold=req.threshold,
            engine=req.engine,
            model=req.model,
        )
    except service.DetectorUnavailable as exc:  # detector needs a key/dep not configured
        raise HTTPException(400, str(exc)) from exc
    except Exception as exc:  # noqa: BLE001 - provider/model failure at score time
        raise HTTPException(502, f"score failed: {type(exc).__name__}: {exc}") from exc
    return ScoreResponse(**r.__dict__)


@app.post("/attack", response_model=AttackResponse)
def attack(req: AttackRequest) -> AttackResponse:
    if req.detector not in service.all_detectors():
        raise HTTPException(400, f"unknown detector {req.detector!r}")
    if req.attack not in service.available_attacks():
        raise HTTPException(400, f"unknown attack {req.attack!r}")
    if req.defense not in service.available_defenses_():
        raise HTTPException(400, f"unknown defense {req.defense!r}")
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
    except ValueError as exc:  # llm attack/detector without a configured provider
        raise HTTPException(400, str(exc)) from exc
    except Exception as exc:  # noqa: BLE001 - provider/model failure, keep it a 502
        raise HTTPException(502, f"attack failed: {type(exc).__name__}: {exc}") from exc
    return AttackResponse(**r.__dict__)


@app.post("/triage/email", response_model=EmailTriageResponse)
def triage_email_message(req: EmailTriageRequest) -> EmailTriageResponse:
    """Triage raw email locally without fetching links or opening attachments."""
    if req.detector not in service.all_detectors():
        raise HTTPException(400, f"unknown detector {req.detector!r}")
    try:
        result = triage_email(
            req.raw_email.encode("utf-8", errors="surrogateescape"),
            detector_name=req.detector,
            threshold=req.threshold,
            engine=req.engine,
            model=req.model,
        )
    except service.DetectorUnavailable as exc:
        raise HTTPException(400, str(exc)) from exc
    except (EmailTooLarge, ValueError) as exc:
        raise HTTPException(400, str(exc)) from exc
    except Exception as exc:  # noqa: BLE001 - provider failure at score time
        raise HTTPException(502, f"triage failed: {type(exc).__name__}: {exc}") from exc
    return EmailTriageResponse(**result.as_dict())


@app.post("/proof/email")
def prove_email_message(req: LureProofRequest) -> dict:
    """Create minimized unsigned evidence; issuer signing is an offline operation."""
    if req.detector not in service.all_detectors():
        raise HTTPException(400, f"unknown detector {req.detector!r}")
    try:
        return create_email_proof(
            req.raw_email.encode("utf-8", errors="surrogateescape"),
            detector_name=req.detector,
            threshold=req.threshold,
            engine=req.engine,
            model=req.model,
            privacy_profile=req.privacy_profile,
            nonce=req.nonce,
        )
    except service.DetectorUnavailable as exc:
        raise HTTPException(400, str(exc)) from exc
    except (EmailTooLarge, ValueError) as exc:
        raise HTTPException(400, str(exc)) from exc
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(502, f"proof creation failed: {type(exc).__name__}: {exc}") from exc


@app.post("/proof/verify", response_model=LureProofVerifyResponse)
def verify_lureproof(req: LureProofVerifyRequest) -> LureProofVerifyResponse:
    public_key = req.public_key_pem.encode("utf-8") if req.public_key_pem else None
    return LureProofVerifyResponse(
        **verify_proof(req.proof, public_key, req.require_signature)
    )


@app.get("/")
def index() -> FileResponse:
    return FileResponse(os.path.join(_STATIC, "index.html"))


# Serve any other static assets (currently just the single-page demo).
app.mount("/static", StaticFiles(directory=_STATIC), name="static")
