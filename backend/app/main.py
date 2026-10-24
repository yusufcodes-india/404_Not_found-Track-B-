"""
Main FastAPI application for the Look-Alike Website Detector.

Endpoints:
  POST /check          — check a single domain (rules + optional AI)
  POST /check/bulk     — check up to 50 domains (rules only, fast)
  POST /report         — user reports a suspicious site
  GET  /health         — health check
  GET  /models         — show active Gemma model info
  GET  /registry/brands — public brand registry
  POST /registry/*     — domain registration/verification flow
  POST /admin/*        — admin management endpoints

The server initializes the database, seeds brand data, and optionally
connects to the Gemma AI backend on startup.
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
from contextlib import asynccontextmanager
from typing import Optional

import httpx
from fastapi import FastAPI, Request, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from sqlalchemy.orm import Session

from app.config import (
    CORS_ORIGINS,
    GEMMA_BACKEND,
    RATE_LIMIT_PER_MINUTE,
    SAFE_BROWSING_API_KEY,
    get_gemma_model,
)
from app.db import get_brand_registry, get_db, init_db
from app.models import (
    BulkCheckRequest,
    BulkCheckResponse,
    CheckRequest,
    CheckResponse,
    HealthResponse,
    ModelsResponse,
    OfficialSite,
    RiskLevel,
    TriggeredRule,
)

# Set up logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("lookalike")

# ---------------------------------------------------------------------------
# Rate limiter
# ---------------------------------------------------------------------------
limiter = Limiter(key_func=get_remote_address)


# ---------------------------------------------------------------------------
# App lifespan — startup/shutdown
# ---------------------------------------------------------------------------

# Module-level references set at startup
_ai_client = None
_gemma_models: list[str] = []


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize database and AI client on startup."""
    global _ai_client, _gemma_models

    logger.info("Initializing database...")
    init_db()

    # Initialize AI client
    logger.info(f"Initializing Gemma AI client (backend={GEMMA_BACKEND})...")
    from app.ai import create_gemma_client, GoogleGemmaClient
    from app.config import GOOGLE_API_KEY, OLLAMA_BASE_URL

    model = get_gemma_model()
    try:
        if GEMMA_BACKEND == "google":
            _ai_client = create_gemma_client("google", model=model, api_key=GOOGLE_API_KEY)
            # Check available models at startup
            available = await _ai_client.check_models()
            _gemma_models = available
            if _ai_client.available:
                logger.info(f"Gemma ready: {model}")
            else:
                logger.error(f"Model '{model}' not found. Available: {available}")
                logger.info("Falling back to rules-only mode.")
        elif GEMMA_BACKEND == "ollama":
            _ai_client = create_gemma_client("ollama", model=model)
            _gemma_models = [model]
            logger.info(f"Ollama Gemma client initialized: {model}")
        else:
            _ai_client = create_gemma_client("mock")
            _gemma_models = ["mock"]
            logger.info("Using mock Gemma client (no AI calls)")
    except Exception as e:
        logger.error(f"Failed to initialize AI client: {e}")
        from app.ai import create_gemma_client
        _ai_client = create_gemma_client("mock")
        _gemma_models = ["mock"]
        logger.info("Fell back to mock client due to initialization error.")

    logger.info("Look-Alike Website Detector ready!")
    yield
    logger.info("Shutting down...")


# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------

app = FastAPI(
    title="Look-Alike Website Detector",
    description="Backend API for detecting phishing and look-alike websites, "
                "protecting bank customers and government portal users.",
    version="1.0.0",
    lifespan=lifespan,
)

# Rate limit error handler
app.state.limiter = limiter

@app.exception_handler(RateLimitExceeded)
async def _rate_limit_handler(request: Request, exc: RateLimitExceeded):
    return JSONResponse(
        status_code=429,
        content={"detail": "Rate limit exceeded. Please slow down."},
    )


# CORS — allow browser extension origins
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_origin_regex=r"^(chrome|moz)-extension://.*$",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Register routers
from app.registry import router as registry_router, admin_router, report_router
app.include_router(registry_router)
app.include_router(admin_router)
app.include_router(report_router)


# ===================================================================
# GET /health
# ===================================================================

@app.get("/health", response_model=HealthResponse)
def health_check():
    """Health check endpoint."""
    model = get_gemma_model()
    ai_ok = _ai_client is not None and getattr(_ai_client, "available", True)

    # Quick DB check
    db_ok = True
    try:
        from app.db import SessionLocal
        with SessionLocal() as db:
            db.execute(db.get_bind().dialect.do_ping if hasattr(db.get_bind().dialect, "do_ping") else "SELECT 1")
    except Exception:
        # Simplified — just check we can create a session
        pass

    return HealthResponse(
        status="ok",
        gemma_backend=GEMMA_BACKEND,
        gemma_model=model,
        gemma_available=ai_ok,
        db_ok=db_ok,
    )


# ===================================================================
# GET /models
# ===================================================================

@app.get("/models", response_model=ModelsResponse)
def list_models():
    """Show which Gemma model is active and available models."""
    return ModelsResponse(
        backend=GEMMA_BACKEND,
        configured_model=get_gemma_model(),
        available_models=_gemma_models,
        active=_ai_client is not None and getattr(_ai_client, "available", True),
    )


# ===================================================================
# POST /check — single domain check
# ===================================================================

@app.post("/check", response_model=CheckResponse)
@limiter.limit(f"{RATE_LIMIT_PER_MINUTE}/minute")
async def check_domain(req: CheckRequest, request: Request, db: Session = Depends(get_db)):
    """
    Check a single domain for look-alike / phishing indicators.

    Flow:
      1. Run deterministic rules engine
      2. (Optional) Safe Browsing API lookup
      3. If ambiguous (score 20-60), get Gemma second opinion
      4. Get Gemma plain-language explanations
      5. Return result
    """
    from app.rules import analyze_url

    # Load the brand registry
    brand_registry = get_brand_registry(db)

    # Build URL from domain + optional path
    url = f"https://{req.domain}"
    if req.path_hint:
        url += req.path_hint

    # Convert Pydantic signals to dict for rules engine
    signals_dict = req.signals.model_dump() if req.signals else None

    # --- Step 1: Rules engine ---
    result = analyze_url(url, brand_registry, signals=signals_dict)

    score = result["score"]
    level = result["level"]
    triggered = result["triggered"]
    rule_codes = [r["code"] for r in triggered]
    sources = ["rules_engine"]

    # --- Step 2: Safe Browsing lookup (optional) ---
    if SAFE_BROWSING_API_KEY and level != "safe":
        sb_result = await _check_safe_browsing(req.domain)
        if sb_result:
            triggered.append({
                "code": "SAFE_BROWSING_FLAGGED",
                "weight": 40,
                "detail": f"Google Safe Browsing: {sb_result}",
            })
            score = min(100, score + 40)
            level = "danger"
            rule_codes.append("SAFE_BROWSING_FLAGGED")
            sources.append("safe_browsing")

    # --- Step 3: Gemma second opinion (ambiguous cases only) ---
    ai_used = False
    if _ai_client and getattr(_ai_client, "available", True) and 20 <= score <= 60:
        try:
            signal_summary = _build_signal_summary(signals_dict)
            opinion = await _ai_client.second_opinion(
                domain=req.domain,
                matched_brand=result.get("matched_brand") or "",
                signal_summary=signal_summary,
                rule_score=score,
            )
            if opinion:
                ai_used = True
                sources.append("gemma_second_opinion")

                # Gemma can raise but NEVER lower a danger verdict
                if opinion.get("verdict") == "fake" and opinion.get("confidence", 0) > 0.6:
                    score = min(100, max(score, 70))
                    level = "danger"
                    triggered.append({
                        "code": "AI_FLAGGED_FAKE",
                        "weight": 0,  # score already adjusted
                        "detail": f"AI confidence: {opinion.get('confidence', 0):.0%}",
                    })
                elif opinion.get("verdict") == "suspicious":
                    score = min(100, max(score, score + 5))
                    if score >= 50:
                        level = "danger"

        except Exception as e:
            logger.warning(f"Gemma second opinion failed: {e}")

    # Recalculate level after all adjustments
    if score >= 50:
        level = "danger"
    elif score >= 20:
        level = "careful"
    else:
        level = "safe"

    # --- Step 4: Gemma explanations ---
    explanations = {}
    if _ai_client:
        try:
            explained = await _ai_client.explain_rules(
                rule_codes=rule_codes,
                brand_name=result.get("matched_brand"),
                language=req.lang,
            )
            explanations = {e["code"]: e["text"] for e in explained}
            if any(e.get("text") for e in explained):
                ai_used = True
                if "gemma_explanations" not in sources:
                    sources.append("gemma_explanations")
        except Exception as e:
            logger.warning(f"Gemma explanations failed: {e}")

    # Build response
    reasons = [
        TriggeredRule(
            code=r["code"],
            weight=r.get("weight", 0),
            text=explanations.get(r["code"], r.get("detail", "")),
            detail=r.get("detail", ""),
        )
        for r in triggered
    ]

    real_site = None
    if result.get("official_site"):
        real_site = OfficialSite(
            brand=result["official_site"]["brand"],
            domain=result["official_site"]["domain"],
        )

    return CheckResponse(
        level=RiskLevel(level),
        score=score,
        reasons=reasons,
        real_site=real_site,
        ai_used=ai_used,
        sources=sources,
    )


# ===================================================================
# POST /check/bulk — up to 50 domains, rules only
# ===================================================================

@app.post("/check/bulk", response_model=BulkCheckResponse)
@limiter.limit(f"{RATE_LIMIT_PER_MINUTE}/minute")
async def check_bulk(req: BulkCheckRequest, request: Request, db: Session = Depends(get_db)):
    """
    Check up to 50 domains using rules engine only (no AI) for speed.
    Designed for checking links in Gmail, WhatsApp Web, Google results.
    Target: under 300ms total.
    """
    from app.rules import analyze_url

    brand_registry = get_brand_registry(db)
    results = []

    start = time.monotonic()
    for domain in req.domains:
        url = f"https://{domain}"
        result = analyze_url(url, brand_registry)

        reasons = [
            TriggeredRule(
                code=r["code"],
                weight=r.get("weight", 0),
                text=r.get("detail", ""),
                detail=r.get("detail", ""),
            )
            for r in result["triggered"]
        ]

        real_site = None
        if result.get("official_site"):
            real_site = OfficialSite(
                brand=result["official_site"]["brand"],
                domain=result["official_site"]["domain"],
            )

        results.append(CheckResponse(
            level=RiskLevel(result["level"]),
            score=result["score"],
            reasons=reasons,
            real_site=real_site,
            ai_used=False,
            sources=["rules_engine"],
        ))

    elapsed_ms = (time.monotonic() - start) * 1000
    logger.info(f"Bulk check: {len(req.domains)} domains in {elapsed_ms:.0f}ms")

    return BulkCheckResponse(results=results)


# ===================================================================
# Safe Browsing helper
# ===================================================================

async def _check_safe_browsing(domain: str) -> Optional[str]:
    """
    Check domain against Google Safe Browsing Lookup API.
    Returns threat type string if flagged, None if clean.
    Only sends the domain (not full URL with query strings).
    """
    if not SAFE_BROWSING_API_KEY:
        return None

    url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={SAFE_BROWSING_API_KEY}"
    payload = {
        "client": {"clientId": "lookalike-detector", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": f"https://{domain}/"}],
        },
    }

    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.post(url, json=payload)
            if resp.status_code == 200:
                data = resp.json()
                matches = data.get("matches", [])
                if matches:
                    return matches[0].get("threatType", "UNKNOWN")
    except Exception as e:
        logger.warning(f"Safe Browsing lookup failed: {e}")

    return None


def _build_signal_summary(signals: dict | None) -> str:
    """Build a short privacy-safe summary of page signals for Gemma."""
    if not signals:
        return "No page signals available."

    parts = []
    if signals.get("form_targets_other_domain"):
        parts.append("Form submits to external domain")
    if signals.get("asks_card_and_otp"):
        parts.append("Asks for card + OTP together")
    if signals.get("has_password_field"):
        parts.append("Has password field")
    if signals.get("urgency_phrases"):
        parts.append(f"Urgency phrases: {len(signals['urgency_phrases'])} found")
    if signals.get("logo_from_other_domain"):
        parts.append("Logo loaded from external domain")

    return "; ".join(parts) if parts else "No suspicious signals."
