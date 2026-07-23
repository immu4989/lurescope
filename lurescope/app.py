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
    ScoreRequest,
    ScoreResponse,
)

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
    )


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


@app.get("/")
def index() -> FileResponse:
    return FileResponse(os.path.join(_STATIC, "index.html"))


# Serve any other static assets (currently just the single-page demo).
app.mount("/static", StaticFiles(directory=_STATIC), name="static")
