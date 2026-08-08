"""Request/response schemas for the API."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class ScoreRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=20000, description="Message to score")
    detector: str = Field("tfidf-logreg", description="Detector to use")
    threshold: Optional[float] = Field(
        None, ge=0.0, le=1.0,
        description="Explicit threshold override; omit to use a configured validated policy",
    )
    engine: Optional[str] = Field(None, description="Provider engine for the llm-judge detector")
    model: Optional[str] = Field(None, description="Provider model id for the llm-judge detector")


class ScoreResponse(BaseModel):
    text: str
    detector: str
    fraud_probability: float
    label: str
    threshold: float
    signals: List[str] = Field(
        default_factory=list, description="Words in the text the detector keys on"
    )
    policy_id: Optional[str] = None
    threshold_source: str = "default"


class AttackRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=20000)
    attack: str = Field(..., description="Attack id, e.g. homoglyph / leet / llm-paraphrase")
    detector: str = Field("tfidf-logreg")
    threshold: float = Field(0.5, ge=0.0, le=1.0)
    engine: Optional[str] = Field(None, description="Provider engine for llm-* attacks/detector")
    model: Optional[str] = Field(None, description="Provider model id for llm-* attacks/detector")
    defense: str = Field(
        "none", description="Defense applied to the attacked text before re-scoring, e.g. normalize"
    )


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
    defense: str = "none"
    defended_text: Optional[str] = None
    defended_probability: Optional[float] = None
    defended_flagged: Optional[bool] = None
    defense_recovered: Optional[bool] = None
    defended_evaded: Optional[bool] = None


class DetectorInfo(BaseModel):
    name: str
    kind: str
    always_on: bool
    requires: Optional[str] = None


class CapabilitiesResponse(BaseModel):
    detectors: List[str]  # always-on detectors (the demo default set)
    detector_catalog: List[DetectorInfo]  # every requestable detector + its requirement
    attacks: List[str]
    defenses: List[str]
    default_detector: str
    workflows: List[str] = Field(default_factory=list)


class EmailTriageRequest(BaseModel):
    raw_email: str = Field(
        ..., min_length=1, max_length=5 * 1024 * 1024,
        description="Raw RFC 5322 email source; parsed locally and never dereferenced",
    )
    detector: str = Field("tfidf-logreg")
    threshold: Optional[float] = Field(None, ge=0.0, le=1.0)
    engine: Optional[str] = None
    model: Optional[str] = None


class TriageEvidence(BaseModel):
    code: str
    severity: str
    title: str
    detail: str


class EmailTriageResponse(BaseModel):
    schema_version: int
    risk_tier: str
    recommended_action: str
    detector: str
    content_probability: float
    content_label: str
    threshold: float
    threshold_source: str
    policy_id: Optional[str] = None
    subject: str
    from_address: Optional[str] = None
    reply_to: Optional[str] = None
    recipients: List[str]
    message_id: Optional[str] = None
    signals: List[str]
    evidence: List[TriageEvidence]
    urls: List[str]
    attachments: List[str]


class LureProofRequest(EmailTriageRequest):
    """The same bounded raw-email input, producing minimized evidence."""


class LureProofVerifyRequest(BaseModel):
    proof: Dict[str, Any]


class LureProofVerifyResponse(BaseModel):
    valid: bool
    digest: str
    errors: List[str]
