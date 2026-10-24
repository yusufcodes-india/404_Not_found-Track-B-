"""
Configuration module for Look-Alike Website Detector.
Reads settings from environment variables / .env file.
"""

import os
from pathlib import Path
from dotenv import load_dotenv

# Load .env from project root
_env_path = Path(__file__).resolve().parent.parent / ".env"
load_dotenv(_env_path)


# ---------------------------------------------------------------------------
# Gemma AI configuration
# ---------------------------------------------------------------------------
GEMMA_BACKEND: str = os.getenv("GEMMA_BACKEND", "mock")  # google | ollama | mock
GEMMA_MODEL: str | None = os.getenv("GEMMA_MODEL")        # None → use default per backend
GOOGLE_API_KEY: str | None = os.getenv("GOOGLE_API_KEY")

# Default models per backend
DEFAULT_MODELS = {
    "google": "gemma-4-26b-a4b-it",
    "ollama": "gemma4:e4b",
    "mock": "mock",
}

def get_gemma_model() -> str:
    """Return the configured Gemma model, falling back to backend default."""
    return GEMMA_MODEL or DEFAULT_MODELS.get(GEMMA_BACKEND, "mock")


# ---------------------------------------------------------------------------
# Google Safe Browsing (optional)
# ---------------------------------------------------------------------------
SAFE_BROWSING_API_KEY: str | None = os.getenv("SAFE_BROWSING_API_KEY")


# ---------------------------------------------------------------------------
# Admin / Auth
# ---------------------------------------------------------------------------
ADMIN_TOKEN: str = os.getenv("ADMIN_TOKEN", "changeme-admin-token")


# ---------------------------------------------------------------------------
# Ollama endpoint
# ---------------------------------------------------------------------------
OLLAMA_BASE_URL: str = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434/v1")


# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------
DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///./lookalike.db")


# ---------------------------------------------------------------------------
# Rate limiting
# ---------------------------------------------------------------------------
RATE_LIMIT_PER_MINUTE: int = int(os.getenv("RATE_LIMIT_PER_MINUTE", "60"))


# ---------------------------------------------------------------------------
# CORS — allow browser extension origins
# ---------------------------------------------------------------------------
CORS_ORIGINS: list[str] = [
    "chrome-extension://*",
    "moz-extension://*",
    "http://localhost:3000",   # dev frontend
    "http://localhost:8080",   # dev frontend alt
]


# ---------------------------------------------------------------------------
# Server / Port / Railway
# ---------------------------------------------------------------------------
PORT: int = int(os.getenv("PORT", "8000"))
RAILWAY_PUBLIC_DOMAIN: str | None = os.getenv("RAILWAY_PUBLIC_DOMAIN")
APP_BASE_URL: str = os.getenv(
    "APP_BASE_URL",
    f"https://{RAILWAY_PUBLIC_DOMAIN}" if RAILWAY_PUBLIC_DOMAIN else f"http://localhost:{PORT}"
)


# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = PROJECT_ROOT / "data"
BRANDS_FILE = DATA_DIR / "brands.json"
