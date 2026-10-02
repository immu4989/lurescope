"""Request/response schemas for the API."""

from __future__ import annotations

import base64
import binascii
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

MAX_EMAIL_INPUT_BYTES = 5 * 1024 * 1024


class _StrictRequest(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid", str_min_length=1, str_max_length=512)

    @field_validator("*")
    @classmethod
    def no_lone_surrogates(cls, value):
        if isinstance(value, str) and any(0xD800 <= ord(c) <= 0xDFFF for c in value):
            raise ValueError("request strings must be valid Unicode")
        return value


class ScoreRequest(_StrictRequest):
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


class AttackRequest(_StrictRequest):
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


class SecurityStatusResponse(BaseModel):
    mode: str
    authentication_required: bool
    rate_limit_per_minute: Optional[int] = None
    provider_daily_limit: Optional[int] = None
    allowed_detectors: List[str] = Field(default_factory=list)
    provider_overrides_restricted: bool
    limitations: List[str] = Field(default_factory=list)


class RiskControlInfo(BaseModel):
    method: str
    risk: str
    confidence: float
    validation_negatives: int
    false_positives: int
    empirical_fpr: float
    upper_confidence_bound: float
    hypothesis_p_value: float
    threshold_grid_size: int


class PolicyStatusResponse(BaseModel):
    configured: bool
    assurance_status: str
    schema_version: Optional[int] = None
    policy_id: Optional[str] = None
    detector: Optional[str] = None
    task: Optional[str] = None
    threshold: Optional[float] = None
    objective: Optional[str] = None
    target_fpr: Optional[float] = None
    validation_records: Optional[int] = None
    validation_sha256: Optional[str] = None
    evaluation_sha256: Optional[str] = None
    validation_true_positives: Optional[int] = None
    validation_recall: Optional[float] = None
    created_at: Optional[str] = None
    risk_control: Optional[RiskControlInfo] = None
    limitations: List[str] = Field(default_factory=list)


class EmailTriageRequest(_StrictRequest):
    raw_email: Optional[str] = Field(
        None, min_length=1, max_length=MAX_EMAIL_INPUT_BYTES,
        description="UTF-8 email text; supply this OR raw_email_base64, not both",
    )
    raw_email_base64: Optional[str] = Field(
        None, min_length=1, max_length=4 * ((MAX_EMAIL_INPUT_BYTES + 2) // 3),
        description="Canonical base64 of original RFC 5322 bytes, preserving non-UTF-8 mail",
    )
    detector: str = Field("tfidf-logreg")
    threshold: Optional[float] = Field(None, ge=0.0, le=1.0)
    engine: Optional[str] = None
    model: Optional[str] = None

    def email_bytes(self) -> bytes:
        if (self.raw_email is None) == (self.raw_email_base64 is None):
            raise ValueError("supply exactly one email representation")
        if self.raw_email is not None:
            payload = self.raw_email.encode("utf-8")
        else:
            try:
                payload = base64.b64decode(self.raw_email_base64, validate=True)
            except (ValueError, binascii.Error) as exc:
                raise ValueError("invalid email base64") from exc
            if base64.b64encode(payload).decode("ascii") != self.raw_email_base64:
                raise ValueError("email base64 must be canonical")
        if not 1 <= len(payload) <= MAX_EMAIL_INPUT_BYTES:
            raise ValueError("email bytes exceed the intake bounds")
        return payload

    @model_validator(mode="after")
    def validate_email_representation(self):
        self.email_bytes()
        return self


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

    privacy_profile: str = Field(
        "salted-commitment", pattern="^(salted-commitment|correlatable)$"
    )
    nonce: Optional[str] = Field(None, min_length=8, max_length=256)


class LureProofVerifyRequest(_StrictRequest):
    proof: Dict[str, Any]
    public_key_pem: Optional[str] = Field(None, max_length=16_384)
    require_signature: bool = False


class LureProofVerifyResponse(BaseModel):
    valid: bool
    schema_valid: bool
    authenticated: bool
    artifact_type: str
    statement_sha256: str
    signature_count: int
    key_ids: List[str]
    errors: List[str]
    warnings: List[str]
