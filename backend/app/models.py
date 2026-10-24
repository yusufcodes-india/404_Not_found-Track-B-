"""
Pydantic v2 models for the Look-Alike Website Detector API.
These define request/response shapes and DB-serialization schemas.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


# ===================================================================
# Enums
# ===================================================================

class RiskLevel(str, Enum):
    """Risk level returned by the rules engine."""
    SAFE = "safe"
    CAREFUL = "careful"
    DANGER = "danger"


class BrandCategory(str, Enum):
    BANK = "bank"
    GOVERNMENT = "government"
    UPI = "upi"
    WALLET = "wallet"
    OTHER = "other"


class BrandStatus(str, Enum):
    VERIFIED = "verified"
    PENDING = "pending"
    DISPUTED = "disputed"


class AIVerdict(str, Enum):
    GENUINE = "genuine"
    SUSPICIOUS = "suspicious"
    FAKE = "fake"


# ===================================================================
# Page signals (sent by the browser content script)
# ===================================================================

class PageSignals(BaseModel):
    """Signals extracted by the browser extension's content script."""
    form_targets_other_domain: bool = False
    asks_card_and_otp: bool = False
    urgency_phrases: list[str] = Field(default_factory=list)
    logo_from_other_domain: Optional[str] = None
    has_password_field: bool = False
    external_form_action: Optional[str] = None


# ===================================================================
# /check endpoint
# ===================================================================

class CheckRequest(BaseModel):
    """Request body for POST /check."""
    domain: str = Field(..., min_length=1, max_length=253, description="Domain to check")
    path_hint: Optional[str] = Field(None, max_length=500, description="Optional URL path (no query strings)")
    signals: Optional[PageSignals] = None
    lang: str = Field("en", pattern=r"^(en|hi|mr|ta|bn)$")


class TriggeredRule(BaseModel):
    """A single triggered rule in the check result."""
    code: str
    weight: int
    text: str = ""        # plain-language explanation
    detail: str = ""      # technical detail (for devs)


class OfficialSite(BaseModel):
    """Info about the real official site when a lookalike is detected."""
    brand: str
    domain: str


class CheckResponse(BaseModel):
    """Response body for POST /check."""
    level: RiskLevel
    score: int = Field(..., ge=0, le=100)
    reasons: list[TriggeredRule]
    real_site: Optional[OfficialSite] = None
    ai_used: bool = False
    sources: list[str] = Field(default_factory=list)


class BulkCheckRequest(BaseModel):
    """Request body for POST /check/bulk (up to 50 domains)."""
    domains: list[str] = Field(..., min_length=1, max_length=50)


class BulkCheckResponse(BaseModel):
    """Response body for POST /check/bulk."""
    results: list[CheckResponse]


# ===================================================================
# /report endpoint
# ===================================================================

class ReportRequest(BaseModel):
    """User report of a suspicious domain."""
    domain: str = Field(..., min_length=1, max_length=253)
    reason: str = Field("", max_length=500)


class ReportResponse(BaseModel):
    id: int
    domain: str
    status: str = "received"


# ===================================================================
# Registry — Brand management
# ===================================================================

class BrandOut(BaseModel):
    """Public brand info returned by the registry."""
    id: int
    name: str
    category: BrandCategory
    official_domains: list[str]
    status: BrandStatus
    verified_at: Optional[datetime] = None


class BrandRegistryResponse(BaseModel):
    """Response for GET /registry/brands."""
    version: int
    brands: list[BrandOut]


# ===================================================================
# Registry — Domain registration flow
# ===================================================================

class RegisterRequest(BaseModel):
    """POST /registry/register — company requests domain verification."""
    company_legal_name: str = Field(..., min_length=1, max_length=200)
    registration_number: str = Field(..., min_length=1, max_length=100)
    country: str = Field("IN", max_length=3)
    domain: str = Field(..., min_length=1, max_length=253)
    contact_email: str = Field(..., min_length=5, max_length=200)
    brand_name: str = Field(..., min_length=1, max_length=100)


class RegisterResponse(BaseModel):
    """Response for POST /registry/register."""
    challenge_id: int
    dns_record: str         # e.g. "_lookalike-challenge.example.com"
    txt_value: str           # e.g. "vc-verify=abc123"
    expires_at: datetime
    email_verification: str  # instructions or demo link


class VerifyDomainRequest(BaseModel):
    """POST /registry/verify-domain — verify DNS TXT record."""
    challenge_id: int
    domain: str


class VerifyDomainResponse(BaseModel):
    verified: bool
    message: str


# ===================================================================
# Registry — Brand evidence
# ===================================================================

class EvidenceRequest(BaseModel):
    """POST /registry/evidence — upload brand evidence for review."""
    brand_name: str
    trademark_number: Optional[str] = None
    jurisdiction: Optional[str] = None
    authorization_letter_text: Optional[str] = None


class EvidenceResponse(BaseModel):
    id: int
    summary: str
    inconsistencies: list[str] = Field(default_factory=list)


# ===================================================================
# Admin endpoints
# ===================================================================

class AdminBrandAction(BaseModel):
    """Admin action on a brand registration."""
    brand_id: int
    action: str = Field(..., pattern=r"^(approve|reject|dispute)$")
    notes: str = ""


# ===================================================================
# AI / Gemma second opinion
# ===================================================================

class GemmaSecondOpinion(BaseModel):
    """Structured response from Gemma's second-opinion classifier."""
    verdict: AIVerdict
    confidence: float = Field(..., ge=0.0, le=1.0)
    reasons: list[str] = Field(default_factory=list)


# ===================================================================
# Health / models endpoints
# ===================================================================

class HealthResponse(BaseModel):
    status: str = "ok"
    gemma_backend: str
    gemma_model: str
    gemma_available: bool
    db_ok: bool


class ModelsResponse(BaseModel):
    backend: str
    configured_model: str
    available_models: list[str]
    active: bool
