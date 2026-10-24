# 404_Not_found - Track B: Look-Alike Website Detector

A comprehensive security solution designed to protect everyday citizens, banking customers, and government portal users from deceptive phishing websites, typosquats, and malicious clones.

[![Deploy on Railway](https://railway.com/button.svg)](https://railway.com/new)

---

## Repository Structure

```text
404_Not_found-Track-B-/
├── backend/                  # FastAPI & Gemma 4 AI Detection Engine
│   ├── app/                  # Application code (rules engine, API, AI client, DB)
│   ├── data/                 # 50 verified Indian brands seed & benchmark datasets
│   ├── tests/                # 73 unit tests (100% pass)
│   ├── scripts/              # Evaluation harness (100% TPR, 0% FPR)
│   ├── Dockerfile            # Container definition for Railway / Docker
│   ├── Procfile              # Process runner configuration
│   ├── railway.json          # Railway cloud deployment configuration
│   ├── requirements.txt      # Python dependencies
│   ├── run.sh                # Local execution script
│   └── README.md             # Detailed backend architecture & API reference
└── (extension / frontend)    # Browser extension / client code
```

---

## Backend Highlights

- **Hybrid Architecture**: Ultra-fast deterministic rules engine (0.28ms per check) + Google Gemma 4 AI for plain-language multilingual explanations (English, Hindi, etc.) and second-opinion edge-case classification.
- **Safety Invariant**: Deterministic rules are the ultimate source of truth; Gemma 4 can elevate risk but can never downgrade a Danger verdict.
- **Brand Registry**: 50+ curated Indian brands (SBI, HDFC, ICICI, UIDAI, Income Tax, DigiLocker, Paytm, PhonePe, etc.) with cryptographic DNS TXT domain-control verification.
- **Benchmarked Accuracy**: 100% True Positive Rate, 0% False Positive Rate across 90 evaluation URLs.
- **Production Ready**: Fully dockerized, rate-limited, CORS-enabled for Chrome and Firefox extensions, and ready for 1-click deployment on Railway.

For setup instructions, API documentation, and curl examples, see [`backend/README.md`](./backend/README.md).
