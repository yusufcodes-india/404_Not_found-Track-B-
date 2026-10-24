"""
Database module — SQLAlchemy + SQLite for the Look-Alike Website Detector.

Tables:
  - brands:              Official brand/domain registry
  - verification_challenges: DNS TXT verification tokens
  - brand_evidence:      Trademark / authorization evidence
  - reports:             User-submitted suspicious-site reports
  - audit_log:           Immutable audit trail for all registry changes
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from sqlalchemy import (
    Column,
    DateTime,
    Integer,
    String,
    Text,
    Boolean,
    create_engine,
    event,
)
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from app.config import DATABASE_URL, BRANDS_FILE


# ---------------------------------------------------------------------------
# SQLAlchemy setup
# ---------------------------------------------------------------------------

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False},  # SQLite needs this for FastAPI
    echo=False,
)

# Enable WAL mode for better concurrent read performance
@event.listens_for(engine, "connect")
def _set_sqlite_pragma(dbapi_connection, _connection_record):
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.close()


SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class Base(DeclarativeBase):
    pass


# ---------------------------------------------------------------------------
# Table: brands
# ---------------------------------------------------------------------------

class BrandRow(Base):
    """Official brand with verified domains."""
    __tablename__ = "brands"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(200), nullable=False, index=True)
    category = Column(String(50), nullable=False)  # bank / government / upi / wallet / other
    official_domains = Column(Text, nullable=False)  # JSON array of domain strings
    status = Column(String(20), nullable=False, default="pending")  # verified / pending / disputed
    verified_at = Column(DateTime, nullable=True)
    expires_at = Column(DateTime, nullable=True)  # re-verification due date (90 days)
    version = Column(Integer, nullable=False, default=1)
    created_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc),
                        onupdate=lambda: datetime.now(timezone.utc))

    def get_domains(self) -> list[str]:
        """Parse the JSON domain list."""
        return json.loads(self.official_domains)

    def set_domains(self, domains: list[str]) -> None:
        """Serialize domains to JSON."""
        self.official_domains = json.dumps(domains)


# ---------------------------------------------------------------------------
# Table: verification_challenges
# ---------------------------------------------------------------------------

class VerificationChallenge(Base):
    """DNS TXT challenge for domain-control verification."""
    __tablename__ = "verification_challenges"

    id = Column(Integer, primary_key=True, autoincrement=True)
    company_legal_name = Column(String(200), nullable=False)
    registration_number = Column(String(100), nullable=False)
    country = Column(String(3), nullable=False, default="IN")
    domain = Column(String(253), nullable=False)
    contact_email = Column(String(200), nullable=False)
    brand_name = Column(String(100), nullable=False)
    token = Column(String(64), nullable=False, unique=True)
    verified = Column(Boolean, nullable=False, default=False)
    email_verified = Column(Boolean, nullable=False, default=False)
    email_token = Column(String(64), nullable=True)
    expires_at = Column(DateTime, nullable=False)
    created_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))


# ---------------------------------------------------------------------------
# Table: brand_evidence
# ---------------------------------------------------------------------------

class BrandEvidence(Base):
    """Trademark / authorization evidence uploaded for review."""
    __tablename__ = "brand_evidence"

    id = Column(Integer, primary_key=True, autoincrement=True)
    brand_name = Column(String(100), nullable=False)
    trademark_number = Column(String(100), nullable=True)
    jurisdiction = Column(String(100), nullable=True)
    authorization_letter_text = Column(Text, nullable=True)
    ai_summary = Column(Text, nullable=True)       # Gemma's summary
    ai_inconsistencies = Column(Text, nullable=True)  # JSON array
    reviewed = Column(Boolean, nullable=False, default=False)
    created_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))


# ---------------------------------------------------------------------------
# Table: reports
# ---------------------------------------------------------------------------

class ReportRow(Base):
    """User-submitted suspicious domain report."""
    __tablename__ = "reports"

    id = Column(Integer, primary_key=True, autoincrement=True)
    domain = Column(String(253), nullable=False)
    reason = Column(Text, nullable=True)
    status = Column(String(20), nullable=False, default="received")  # received / investigating / resolved
    created_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))


# ---------------------------------------------------------------------------
# Table: audit_log
# ---------------------------------------------------------------------------

class AuditLogRow(Base):
    """Immutable audit trail for registry changes."""
    __tablename__ = "audit_log"

    id = Column(Integer, primary_key=True, autoincrement=True)
    action = Column(String(50), nullable=False)  # e.g. brand_approved, brand_rejected, domain_verified
    target_type = Column(String(50), nullable=False)  # brand, challenge, evidence
    target_id = Column(Integer, nullable=False)
    details = Column(Text, nullable=True)  # JSON with extra context
    performed_by = Column(String(100), nullable=False, default="system")
    created_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))


# ---------------------------------------------------------------------------
# Database lifecycle
# ---------------------------------------------------------------------------

def init_db() -> None:
    """Create all tables and seed brand data if empty."""
    Base.metadata.create_all(bind=engine)
    _seed_brands_if_empty()


def get_db():
    """FastAPI dependency — yields a DB session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def _seed_brands_if_empty() -> None:
    """Load brands from data/brands.json if the brands table is empty."""
    with SessionLocal() as db:
        count = db.query(BrandRow).count()
        if count > 0:
            return

        if not BRANDS_FILE.exists():
            print(f"[db] Warning: {BRANDS_FILE} not found — skipping seed")
            return

        brands_data = json.loads(BRANDS_FILE.read_text(encoding="utf-8"))
        now = datetime.now(timezone.utc)

        for entry in brands_data:
            row = BrandRow(
                name=entry["name"],
                category=entry.get("category", "other"),
                official_domains=json.dumps(entry.get("official_domains", [])),
                status=entry.get("status", "verified"),
                verified_at=now if entry.get("status") == "verified" else None,
                version=1,
            )
            db.add(row)

        db.commit()
        print(f"[db] Seeded {len(brands_data)} brands from {BRANDS_FILE.name}")


def get_brand_registry(db: Optional[Session] = None) -> list[dict]:
    """
    Return the brand registry as a list of dicts for the rules engine.
    Each dict: {"name": ..., "category": ..., "official_domains": [...], "status": ...}
    """
    close_after = False
    if db is None:
        db = SessionLocal()
        close_after = True

    try:
        rows = db.query(BrandRow).filter(BrandRow.status == "verified").all()
        result = []
        for row in rows:
            result.append({
                "id": row.id,
                "name": row.name,
                "category": row.category,
                "official_domains": row.get_domains(),
                "status": row.status,
            })
        return result
    finally:
        if close_after:
            db.close()


def get_registry_version(db: Session) -> int:
    """Return the max version number across all brands."""
    from sqlalchemy import func
    result = db.query(func.max(BrandRow.version)).scalar()
    return result or 1


def add_audit_log(
    db: Session,
    action: str,
    target_type: str,
    target_id: int,
    details: str = "",
    performed_by: str = "system",
) -> None:
    """Write an immutable audit log entry."""
    entry = AuditLogRow(
        action=action,
        target_type=target_type,
        target_id=target_id,
        details=details,
        performed_by=performed_by,
    )
    db.add(entry)
    db.commit()
