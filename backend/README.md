# Team 404 Not Found — Look-Alike Website Detector Backend API

> **Team**: 404 Not Found  
> **Track**: Track B  
> **Repository**: [yusufcodes-india/404_Not_found-Track-B-](https://github.com/yusufcodes-india/404_Not_found-Track-B-)

[![Deploy on Railway](https://railway.com/button.svg)](https://railway.com/new)
[![GitHub](https://img.shields.io/badge/GitHub-yusufcodes--india%2F404__Not__found--Track--B--blue?logo=github)](https://github.com/yusufcodes-india/404_Not_found-Track-B-)

An intelligent backend protecting everyday citizens, bank customers, and government portal users from phishing scams, typosquatting, and deceptive look-alike domains. Combines high-speed deterministic rules with Google Gemma 4 AI for plain-language explanations in regional languages and second-opinion ambiguity resolution.

---

## Architecture Overview

```text
               +-------------------------------------------------------------+
               |  Browser Extension / Content Script (Chrome / Firefox)     |
               +-------------------------------------------------------------+
                                       |
                 POST /check (JSON: domain, path_hint, signals, lang)
                                       v
               +-------------------------------------------------------------+
               |                 FastAPI Application (app/main.py)           |
               +-------------------------------------------------------------+
                        |                                       |
           (1) Deterministic Rules                 (2) Safe Browsing Lookup
                        v                                       v
          +----------------------------+             +----------------------+
          |     Rules Engine           |             | Google Safe Browsing |
          |   (app/rules.py)           |             | API (Domain-only)    |
          | - Exact/Subdomain match    |             +----------------------+
          | - Levenshtein <= 2         |                        |
          | - Homoglyphs & Punycode    |                        |
          | - Brand in Subdomain/Path  |                        |
          | - Structural Flags (TLDs)  |                        |
          | - Content Script Signals   |                        |
          +----------------------------+                        |
                        |                                       |
                        +-------------------+-------------------+
                                            |
                         Risk Score (0-100) & Level
                                            |
                     +----------------------+----------------------+
                     | (Score between 20 & 60)                     | (All verdicts)
                     v                                             v
        +----------------------------+               +----------------------------+
        | Gemma 4: Second Opinion    |               | Gemma 4: Plain Explainer   |
        | - Cannot lower Danger      |               | - English, Hindi (max 20w) |
        | - Untrusted data isolated  |               | - LRU Cached (instant)     |
        | - 6-second strict timeout  |               | - Template fallback        |
        +----------------------------+               +----------------------------+
                     |                                             |
                     +----------------------+----------------------+
                                            |
                                            v
               +-------------------------------------------------------------+
               |   Standardized Verdict Response                             |
               |   {level, score, reasons, real_site, ai_used, sources}      |
               +-------------------------------------------------------------+
```

---

## Key Design Principles & Guardrails

1. **Deterministic Ground Truth**: Gemma 4 acts as the explainer and advisor; the deterministic rules engine is the ultimate source of truth.
2. **Safety Invariants**:
   - Gemma can **raise** risk but can **NEVER lower a Danger verdict** produced by the rules engine.
   - Gemma can never mark an arbitrary domain as officially verified.
3. **Prompt Injection Defense**: All untrusted inputs (domains, paths, page texts) are wrapped inside delimiter blocks (`[BEGIN UNTRUSTED DATA]` / `[END UNTRUSTED DATA]`) with explicit system instructions to ignore internal commands.
4. **Resilient Fallback**: Strict 6-second timeout on all LLM calls. On timeout or malformed JSON, automatically falls back to built-in template explanations.
5. **Strict Privacy**: Only domain names, matched brand names, and high-level boolean signals are transmitted. No full URLs with query parameters, cookies, or user form entries are ever processed or logged.

---

## Tech Stack

- **Runtime**: Python 3.11+
- **Framework**: FastAPI, Uvicorn, Pydantic v2
- **Database**: SQLite via SQLAlchemy with WAL mode enabled
- **AI / LLM Layer**: `google-genai` SDK (Google AI Studio) & Ollama (OpenAI-compatible endpoint)
- **Domain & String Analysis**: `tldextract`, `rapidfuzz`, `dnspython`, `httpx`
- **Security & Reliability**: `slowapi` rate limiting, CORS extension headers

---

## Setup & Installation

### 1. Clone & Enter Project Directory
```bash
git clone https://github.com/yusufcodes-india/404_Not_found-Track-B-.git
cd 404_Not_found-Track-B-/backend
```

### 2. Configure Environment (`.env`)
Copy the sample environment file:
```bash
cp .env.example .env
```

Edit `.env` based on your chosen Gemma backend:

#### Option A: Mock Mode (Offline Demo / Testing)
No API keys or GPU required:
```ini
GEMMA_BACKEND=mock
ADMIN_TOKEN=changeme-admin-token
```

#### Option B: Google AI Studio (Cloud Gemma 4)
```ini
GEMMA_BACKEND=google
GEMMA_MODEL=gemma-4-26b-a4b-it
GOOGLE_API_KEY=your_google_ai_studio_api_key
ADMIN_TOKEN=changeme-admin-token
```
*Note: At startup, the server inspects available models via `client.models.list()`. If the model is not accessible, it logs a warning and safely falls back to rules-only mode.*

#### Option C: Ollama (Local Self-Hosted Gemma 4)
First, pull and run Gemma 4 locally:
```bash
ollama pull gemma4:e4b
ollama serve
```

Configure `.env`:
```ini
GEMMA_BACKEND=ollama
GEMMA_MODEL=gemma4:e4b
OLLAMA_BASE_URL=http://localhost:11434/v1
ADMIN_TOKEN=changeme-admin-token
```

### 3. Run the Backend
Using the automated run script:
```bash
chmod +x run.sh
./run.sh
```

Or manually with virtual environment:
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

---

## Complete API Reference & Examples

### 1. Health & Model Inspection
#### `GET /health`
```bash
curl -s http://localhost:8000/health
```
**Response:**
```json
{
  "status": "ok",
  "gemma_backend": "mock",
  "gemma_model": "mock",
  "gemma_available": true,
  "db_ok": true
}
```

#### `GET /models`
```bash
curl -s http://localhost:8000/models
```

---

### 2. Website Analysis
#### `POST /check` (Single Domain Check)
Check a domain with page signals and request plain-language explanations in Hindi:
```bash
curl -s -X POST http://localhost:8000/check \
  -H "Content-Type: application/json" \
  -d '{
    "domain": "onlinesbl.sbi",
    "lang": "hi",
    "signals": {
      "asks_card_and_otp": true,
      "form_targets_other_domain": true
    }
  }'
```
**Response:**
```json
{
  "level": "danger",
  "score": 80,
  "reasons": [
    {
      "code": "TYPOSQUAT_BRAND",
      "weight": 25,
      "text": "यह वेबसाइट का नाम State Bank of India से बहुत मिलता-जुलता है — यह नकली हो सकती है।",
      "detail": "Domain 'onlinesbl' is 1 edit(s) away from State Bank of India official domain"
    },
    {
      "code": "FORM_TO_OTHER_DOMAIN",
      "weight": 25,
      "text": "यह पेज आपकी लॉगिन जानकारी दूसरी वेबसाइट पर भेजता है — फ़िशिंग का संकेत।",
      "detail": "Login/payment form submits data to a different domain"
    },
    {
      "code": "ASKS_CARD_PIN_OTP",
      "weight": 30,
      "text": "यह पेज एक साथ कार्ड, PIN और OTP माँगता है — असली बैंक ऐसा कभी नहीं करते।",
      "detail": "Page asks for card details AND OTP/PIN simultaneously"
    }
  ],
  "real_site": {
    "brand": "State Bank of India",
    "domain": "onlinesbi.sbi"
  },
  "ai_used": true,
  "sources": [
    "rules_engine",
    "gemma_explanations"
  ]
}
```

#### `POST /check/bulk` (High-Speed Link Checking)
Evaluate up to 50 URLs in under 300ms for browser extensions monitoring Gmail, WhatsApp Web, or Google Search results:
```bash
curl -s -X POST http://localhost:8000/check/bulk \
  -H "Content-Type: application/json" \
  -d '{
    "domains": [
      "onlinesbi.sbi",
      "hdfcbamk.com",
      "google.com"
    ]
  }'
```

#### `POST /report` (User Phishing Report)
```bash
curl -s -X POST http://localhost:8000/report \
  -H "Content-Type: application/json" \
  -d '{
    "domain": "fake-sbi-portal.xyz",
    "reason": "Received SMS asking to update KYC immediately"
  }'
```

---

### 3. Brand Registry & Domain Verification Flow

#### `GET /registry/brands` (Public Brand Allowlist)
```bash
curl -s http://localhost:8000/registry/brands
```

#### `POST /registry/register` (Initiate Domain Verification)
Issues a DNS TXT challenge:
```bash
curl -s -X POST http://localhost:8000/registry/register \
  -H "Content-Type: application/json" \
  -d '{
    "company_legal_name": "State Bank of India",
    "registration_number": "SBI-REG-001",
    "country": "IN",
    "domain": "onlinesbi.sbi",
    "contact_email": "security@onlinesbi.sbi",
    "brand_name": "State Bank of India"
  }'
```
**Response:**
```json
{
  "challenge_id": 1,
  "dns_record": "_lookalike-challenge.onlinesbi.sbi",
  "txt_value": "vc-verify=hXEFn3w1_hl4_9yG6N1ZewVvuFVo3bKXdHB0YZmSCHM",
  "expires_at": "2026-10-25T16:00:00Z",
  "email_verification": "Demo: verification link printed to server console for security@onlinesbi.sbi"
}
```

#### `POST /registry/verify-domain` (Validate DNS TXT Record)
```bash
curl -s -X POST http://localhost:8000/registry/verify-domain \
  -H "Content-Type: application/json" \
  -d '{
    "challenge_id": 1,
    "domain": "onlinesbi.sbi"
  }'
```

#### `POST /registry/evidence` (Brand Evidence Upload)
Gemma summarizes legal documentation and flags inconsistencies for human reviewers:
```bash
curl -s -X POST http://localhost:8000/registry/evidence \
  -H "Content-Type: application/json" \
  -d '{
    "brand_name": "State Bank of India",
    "trademark_number": "TM-IN-482910",
    "jurisdiction": "India",
    "authorization_letter_text": "We hereby authorize our digital security team to register onlinesbi.sbi."
  }'
```

---

### 4. Admin Management (Bearer Token Protected)

#### `GET /admin/pending`
```bash
curl -s -H "Authorization: Bearer changeme-admin-token" \
  http://localhost:8000/admin/pending
```

#### `POST /admin/action` (Approve / Reject / Dispute Brand)
```bash
curl -s -X POST http://localhost:8000/admin/action \
  -H "Authorization: Bearer changeme-admin-token" \
  -H "Content-Type: application/json" \
  -d '{
    "brand_id": 1,
    "action": "approve",
    "notes": "Verified against MCA corporate records"
  }'
```

#### `GET /admin/audit-log` (Immutable Audit Trail)
```bash
curl -s -H "Authorization: Bearer changeme-admin-token" \
  http://localhost:8000/admin/audit-log
```

---

## Testing & Benchmarks

### Running Unit Tests
73 pytest unit tests covering genuine portals, typosquats, homoglyphs, and false-positive guards:
```bash
.venv/bin/pytest -v
```

### Running Benchmark Evaluation
```bash
.venv/bin/python scripts/evaluate.py
```

**Evaluation Results:**
```text
======================================================================
  LOOK-ALIKE WEBSITE DETECTOR — BENCHMARK EVALUATION
======================================================================
Registry Brands Loaded : 50
Phishing Samples       : 42
Legitimate Samples     : 48
----------------------------------------------------------------------
RESULTS SUMMARY:
  Total URLs Evaluated : 90
  Total Time           : 25.36 ms
  Avg Latency per URL  : 0.28 ms
  Detection Rate (TPR) : 100.00% (42/42)
  False-Positive Rate  : 0.00% (0/48)
  Overall Accuracy     : 100.00%
======================================================================
```

---

## Roadmap

1. **Multi-Factor Authentication (MFA)**: Require TOTP or WebAuthn/FIDO2 for all domain administrator and reviewer actions.
2. **KYB (Know Your Business) Automated Integration**: Integrate automated registrar & corporate registry verification via MCA21 / LEI (Legal Entity Identifier) APIs.
3. **CNAME Fallback Verification**: Add alternative validation for organizations unable to deploy TXT records via dedicated CNAME validation delegates.
4. **Automated 90-Day Re-Verification**: Automated background worker validating DNS TXT records every 90 days, flagging expired records to admin review before delisting.
