"""
Registry module — domain registration, verification, and admin endpoints.

Handles the complete brand registration flow:
  1. Company submits registration request → DNS TXT challenge issued
  2. Company publishes TXT record → system verifies via dnspython
  3. Email verification (demo: prints link to console)
  4. Brand evidence upload → Gemma summarizes for reviewer
  5. Admin reviews and approves/rejects/disputes

All changes are recorded in the audit log.
"""

from __future__ import annotations

import json
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional

import dns.resolver
from fastapi import APIRouter, Depends, Header, HTTPException
from sqlalchemy.orm import Session

from app.config import ADMIN_TOKEN, APP_BASE_URL
from app.db import (
    BrandEvidence,
    BrandRow,
    ReportRow,
    VerificationChallenge,
    add_audit_log,
    get_brand_registry,
    get_db,
    get_registry_version,
)
from app.models import (
    AdminBrandAction,
    BrandOut,
    BrandRegistryResponse,
    BrandStatus,
    EvidenceRequest,
    EvidenceResponse,
    RegisterRequest,
    RegisterResponse,
    ReportRequest,
    ReportResponse,
    VerifyDomainRequest,
    VerifyDomainResponse,
)

router = APIRouter(prefix="/registry", tags=["registry"])
admin_router = APIRouter(prefix="/admin", tags=["admin"])
report_router = APIRouter(prefix="/report", tags=["reports"])


# ---------------------------------------------------------------------------
# Helper: verify admin token
# ---------------------------------------------------------------------------

def _require_admin(authorization: str = Header(...)) -> str:
    """Validate Bearer token for admin endpoints."""
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing Bearer token")
    token = authorization[len("Bearer "):]
    if token != ADMIN_TOKEN:
        raise HTTPException(status_code=403, detail="Invalid admin token")
    return token


# ===================================================================
# GET /registry/brands — public brand list with ETag
# ===================================================================

@router.get("/brands", response_model=BrandRegistryResponse)
def list_brands(db: Session = Depends(get_db)):
    """
    Return the full verified brand registry.
    The extension caches this locally and uses ETag for freshness checks.
    """
    version = get_registry_version(db)
    rows = db.query(BrandRow).filter(BrandRow.status == "verified").all()

    brands = [
        BrandOut(
            id=row.id,
            name=row.name,
            category=row.category,
            official_domains=row.get_domains(),
            status=row.status,
            verified_at=row.verified_at,
        )
        for row in rows
    ]
    return BrandRegistryResponse(version=version, brands=brands)


# ===================================================================
# POST /registry/register — start domain verification
# ===================================================================

@router.post("/register", response_model=RegisterResponse)
def register_domain(req: RegisterRequest, db: Session = Depends(get_db)):
    """
    Start domain-control verification for a company.

    Issues a random DNS TXT challenge and an email verification link.
    The company must:
      1. Publish: _lookalike-challenge.<domain> TXT "vc-verify=<token>"
      2. Click the email verification link sent to contact_email
    """
    # Generate secure random tokens
    dns_token = secrets.token_urlsafe(32)
    email_token = secrets.token_urlsafe(32)
    expiry = datetime.now(timezone.utc) + timedelta(hours=24)

    challenge = VerificationChallenge(
        company_legal_name=req.company_legal_name,
        registration_number=req.registration_number,
        country=req.country,
        domain=req.domain,
        contact_email=req.contact_email,
        brand_name=req.brand_name,
        token=dns_token,
        email_token=email_token,
        expires_at=expiry,
    )
    db.add(challenge)
    db.commit()
    db.refresh(challenge)

    # Audit log
    add_audit_log(
        db, action="challenge_created", target_type="challenge",
        target_id=challenge.id,
        details=json.dumps({"domain": req.domain, "brand": req.brand_name}),
    )

    # Demo mode: print email verification link to console
    email_link = f"{APP_BASE_URL}/registry/verify-email?token={email_token}"
    print(f"\n[DEMO] Email verification link for {req.contact_email}:")
    print(f"  {email_link}\n")

    dns_record = f"_lookalike-challenge.{req.domain}"
    txt_value = f"vc-verify={dns_token}"

    return RegisterResponse(
        challenge_id=challenge.id,
        dns_record=dns_record,
        txt_value=txt_value,
        expires_at=expiry,
        email_verification=f"Demo: verification link printed to server console for {req.contact_email}",
    )


# ===================================================================
# POST /registry/verify-domain — check DNS TXT record
# ===================================================================

@router.post("/verify-domain", response_model=VerifyDomainResponse)
def verify_domain(req: VerifyDomainRequest, db: Session = Depends(get_db)):
    """
    Verify domain ownership by checking the DNS TXT challenge.

    Looks up _lookalike-challenge.<domain> TXT record and compares
    the exact token. SSL certificates are NOT accepted as proof.
    """
    challenge = db.query(VerificationChallenge).filter(
        VerificationChallenge.id == req.challenge_id,
        VerificationChallenge.domain == req.domain,
    ).first()

    if not challenge:
        raise HTTPException(status_code=404, detail="Challenge not found")

    # Check expiry
    now = datetime.now(timezone.utc)
    if challenge.expires_at.replace(tzinfo=timezone.utc) < now:
        return VerifyDomainResponse(verified=False, message="Challenge expired. Please register again.")

    if challenge.verified:
        return VerifyDomainResponse(verified=True, message="Domain already verified.")

    # Perform DNS TXT lookup
    expected_value = f"vc-verify={challenge.token}"
    dns_name = f"_lookalike-challenge.{req.domain}"

    try:
        answers = dns.resolver.resolve(dns_name, "TXT")
        found = False
        for rdata in answers:
            # TXT records come as a list of strings; join them
            txt_value = "".join(s.decode("utf-8") if isinstance(s, bytes) else s for s in rdata.strings)
            if txt_value.strip() == expected_value:
                found = True
                break

        if found:
            challenge.verified = True
            db.commit()
            add_audit_log(
                db, action="domain_verified", target_type="challenge",
                target_id=challenge.id,
                details=json.dumps({"domain": req.domain}),
            )
            return VerifyDomainResponse(verified=True, message="DNS verification successful!")
        else:
            return VerifyDomainResponse(
                verified=False,
                message=f"TXT record found but value doesn't match. Expected: {expected_value}",
            )

    except dns.resolver.NXDOMAIN:
        return VerifyDomainResponse(
            verified=False,
            message=f"DNS record {dns_name} not found. Please add the TXT record and try again.",
        )
    except dns.resolver.NoAnswer:
        return VerifyDomainResponse(
            verified=False,
            message=f"No TXT records found for {dns_name}. Please add the record and try again.",
        )
    except Exception as e:
        return VerifyDomainResponse(
            verified=False,
            message=f"DNS lookup error: {str(e)}",
        )


# ===================================================================
# GET /registry/verify-email — email verification (demo mode)
# ===================================================================

@router.get("/verify-email")
def verify_email(token: str, db: Session = Depends(get_db)):
    """
    Email verification endpoint. In demo mode, the link is printed to console.
    In production, this would be sent via actual email.
    """
    challenge = db.query(VerificationChallenge).filter(
        VerificationChallenge.email_token == token
    ).first()

    if not challenge:
        raise HTTPException(status_code=404, detail="Invalid or expired email token")

    challenge.email_verified = True
    db.commit()

    add_audit_log(
        db, action="email_verified", target_type="challenge",
        target_id=challenge.id,
        details=json.dumps({"email": challenge.contact_email}),
    )

    return {"message": "Email verified successfully!", "domain": challenge.domain}


# ===================================================================
# POST /registry/evidence — upload brand evidence
# ===================================================================

@router.post("/evidence", response_model=EvidenceResponse)
async def submit_evidence(req: EvidenceRequest, db: Session = Depends(get_db)):
    """
    Submit trademark / authorization evidence for a brand.
    Gemma summarizes the evidence for the human reviewer.
    """
    # Import AI client lazily to avoid circular imports
    from app.ai import get_ai_client

    evidence = BrandEvidence(
        brand_name=req.brand_name,
        trademark_number=req.trademark_number,
        jurisdiction=req.jurisdiction,
        authorization_letter_text=req.authorization_letter_text,
    )

    # Use Gemma to summarize the evidence (if available)
    ai_client = get_ai_client()
    evidence_text = _build_evidence_text(req)

    try:
        review = await ai_client.review_brand_evidence(evidence_text, req.brand_name)
        evidence.ai_summary = review.get("summary", "")
        evidence.ai_inconsistencies = json.dumps(review.get("inconsistencies", []))
    except Exception as e:
        print(f"[registry] AI evidence review failed: {e}")
        evidence.ai_summary = "AI review unavailable — manual review required."
        evidence.ai_inconsistencies = json.dumps([])

    db.add(evidence)
    db.commit()
    db.refresh(evidence)

    add_audit_log(
        db, action="evidence_submitted", target_type="evidence",
        target_id=evidence.id,
        details=json.dumps({"brand": req.brand_name}),
    )

    return EvidenceResponse(
        id=evidence.id,
        summary=evidence.ai_summary or "",
        inconsistencies=json.loads(evidence.ai_inconsistencies) if evidence.ai_inconsistencies else [],
    )


def _build_evidence_text(req: EvidenceRequest) -> str:
    """Combine evidence fields into a single text for AI review."""
    parts = [f"Brand: {req.brand_name}"]
    if req.trademark_number:
        parts.append(f"Trademark Number: {req.trademark_number}")
    if req.jurisdiction:
        parts.append(f"Jurisdiction: {req.jurisdiction}")
    if req.authorization_letter_text:
        parts.append(f"Authorization Letter:\n{req.authorization_letter_text}")
    return "\n".join(parts)


# ===================================================================
# POST /report — user reports a suspicious domain
# ===================================================================

@report_router.post("", response_model=ReportResponse)
def submit_report(req: ReportRequest, db: Session = Depends(get_db)):
    """
    Let users flag a suspicious website domain.
    Reports are stored and shown to admins for investigation.
    """
    report = ReportRow(
        domain=req.domain,
        reason=req.reason,
    )
    db.add(report)
    db.commit()
    db.refresh(report)

    return ReportResponse(id=report.id, domain=report.domain)


# ===================================================================
# Admin endpoints (require Bearer ADMIN_TOKEN)
# ===================================================================

@admin_router.get("/pending")
def list_pending(
    _token: str = Depends(_require_admin),
    db: Session = Depends(get_db),
):
    """List all pending brand registrations and verification challenges."""
    challenges = db.query(VerificationChallenge).filter(
        VerificationChallenge.verified == True,  # noqa: E712 — SQLAlchemy needs ==
    ).all()

    pending_brands = db.query(BrandRow).filter(
        BrandRow.status == "pending"
    ).all()

    reports = db.query(ReportRow).filter(
        ReportRow.status == "received"
    ).all()

    return {
        "verified_challenges": [
            {
                "id": c.id,
                "domain": c.domain,
                "brand_name": c.brand_name,
                "company": c.company_legal_name,
                "dns_verified": c.verified,
                "email_verified": c.email_verified,
            }
            for c in challenges
        ],
        "pending_brands": [
            {
                "id": b.id,
                "name": b.name,
                "category": b.category,
                "domains": b.get_domains(),
                "status": b.status,
            }
            for b in pending_brands
        ],
        "reports": [
            {"id": r.id, "domain": r.domain, "reason": r.reason}
            for r in reports
        ],
    }


@admin_router.post("/action")
def admin_brand_action(
    action: AdminBrandAction,
    _token: str = Depends(_require_admin),
    db: Session = Depends(get_db),
):
    """
    Admin approves, rejects, or disputes a brand registration.

    - Approved brands become public with incremented version.
    - A disputed brand cannot change its allowlist until resolved.
    - Re-verification date set to 90 days from approval.
    """
    brand = db.query(BrandRow).filter(BrandRow.id == action.brand_id).first()
    if not brand:
        raise HTTPException(status_code=404, detail="Brand not found")

    now = datetime.now(timezone.utc)

    if action.action == "approve":
        brand.status = "verified"
        brand.verified_at = now
        brand.expires_at = now + timedelta(days=90)  # re-verification due
        brand.version += 1

    elif action.action == "reject":
        brand.status = "pending"  # reset to pending, admin can add notes

    elif action.action == "dispute":
        brand.status = "disputed"

    db.commit()

    add_audit_log(
        db, action=f"brand_{action.action}d", target_type="brand",
        target_id=brand.id,
        details=json.dumps({"notes": action.notes}),
        performed_by="admin",
    )

    return {
        "brand_id": brand.id,
        "name": brand.name,
        "new_status": brand.status,
        "version": brand.version,
    }


@admin_router.post("/approve-challenge")
def approve_challenge(
    challenge_id: int,
    _token: str = Depends(_require_admin),
    db: Session = Depends(get_db),
):
    """
    Approve a verified challenge — creates a new brand entry from the challenge data.
    Both DNS and email must be verified.
    """
    challenge = db.query(VerificationChallenge).filter(
        VerificationChallenge.id == challenge_id,
    ).first()

    if not challenge:
        raise HTTPException(status_code=404, detail="Challenge not found")

    if not challenge.verified:
        raise HTTPException(status_code=400, detail="DNS not verified yet")

    if not challenge.email_verified:
        raise HTTPException(status_code=400, detail="Email not verified yet")

    # Create brand entry as pending (admin can then approve it)
    now = datetime.now(timezone.utc)
    brand = BrandRow(
        name=challenge.brand_name,
        category="other",  # admin can update later
        official_domains=json.dumps([challenge.domain]),
        status="pending",
        version=1,
    )
    db.add(brand)
    db.commit()
    db.refresh(brand)

    add_audit_log(
        db, action="brand_created_from_challenge", target_type="brand",
        target_id=brand.id,
        details=json.dumps({
            "challenge_id": challenge.id,
            "domain": challenge.domain,
            "company": challenge.company_legal_name,
        }),
        performed_by="admin",
    )

    return {
        "brand_id": brand.id,
        "name": brand.name,
        "domain": challenge.domain,
        "status": brand.status,
        "message": "Brand created as pending. Use /admin/action to approve it.",
    }


@admin_router.get("/reports")
def list_reports(
    _token: str = Depends(_require_admin),
    db: Session = Depends(get_db),
):
    """List all user-submitted suspicious domain reports."""
    reports = db.query(ReportRow).order_by(ReportRow.created_at.desc()).all()
    return [
        {
            "id": r.id,
            "domain": r.domain,
            "reason": r.reason,
            "status": r.status,
            "created_at": r.created_at.isoformat() if r.created_at else None,
        }
        for r in reports
    ]


@admin_router.get("/audit-log")
def get_audit_log(
    limit: int = 50,
    _token: str = Depends(_require_admin),
    db: Session = Depends(get_db),
):
    """View the audit log (most recent first)."""
    from app.db import AuditLogRow
    rows = db.query(AuditLogRow).order_by(AuditLogRow.created_at.desc()).limit(limit).all()
    return [
        {
            "id": r.id,
            "action": r.action,
            "target_type": r.target_type,
            "target_id": r.target_id,
            "details": r.details,
            "performed_by": r.performed_by,
            "created_at": r.created_at.isoformat() if r.created_at else None,
        }
        for r in rows
    ]
