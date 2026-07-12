"""Request/response schemas for the API."""

from __future__ import annotations

from typing import List, Optional

from pydantic import BaseModel, Field


class ScoreRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=20000, description="Message to score")
    detector: str = Field("tfidf-logreg", description="Detector to use")
    threshold: float = Field(0.5, ge=0.0, le=1.0)


class ScoreResponse(BaseModel):
    text: str
    detector: str
    fraud_probability: float
    label: str
    threshold: float
    signals: List[str] = Field(
        default_factory=list, description="Words in the text the detector keys on"
    )


class AttackRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=20000)
    attack: str = Field(..., description="Attack id, e.g. homoglyph / leet / llm-paraphrase")
    detector: str = Field("tfidf-logreg")
    threshold: float = Field(0.5, ge=0.0, le=1.0)
    engine: Optional[str] = Field(None, description="Provider engine for llm-* attacks")
    model: Optional[str] = Field(None, description="Provider model id for llm-* attacks")


class AttackResponse(BaseModel):
    detector: str
    attack: str
    original: str
    attacked: str
    clean_probability: float
    attacked_probability: float
    threshold: float
    clean_flagged: bool
    attacked_flagged: bool
    evaded: bool


class CapabilitiesResponse(BaseModel):
    detectors: List[str]
    attacks: List[str]
    default_detector: str
