import uuid
from datetime import datetime
from sqlalchemy import String, Text, DateTime, ForeignKey, JSON, Integer, Float, Boolean, Index
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import UUID
from .db import Base


def _uuid() -> str:
    return str(uuid.uuid4())


class User(Base):
    __tablename__ = "users"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    email: Mapped[str] = mapped_column(String, unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String)
    role: Mapped[str] = mapped_column(String, default="analyst")  # admin | analyst | viewer
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class Investigation(Base):
    __tablename__ = "investigations"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String)
    description: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[str] = mapped_column(String, default="draft")  # draft|running|completed|error
    owner_id: Mapped[str] = mapped_column(String, ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    tags: Mapped[dict] = mapped_column(JSON, default=dict)
    subjects: Mapped[list["Subject"]] = relationship(back_populates="investigation", cascade="all, delete-orphan")
    jobs: Mapped[list["Job"]] = relationship(back_populates="investigation", cascade="all, delete-orphan")
    entities: Mapped[list["Entity"]] = relationship(back_populates="investigation", cascade="all, delete-orphan")
    findings: Mapped[list["Finding"]] = relationship(back_populates="investigation", cascade="all, delete-orphan")


class Subject(Base):
    __tablename__ = "subjects"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    investigation_id: Mapped[str] = mapped_column(String, ForeignKey("investigations.id", ondelete="CASCADE"))
    type: Mapped[str] = mapped_column(String)  # domain|ip|email|username|company|media|document|url
    value: Mapped[str] = mapped_column(String)
    note: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    investigation: Mapped[Investigation] = relationship(back_populates="subjects")


class Job(Base):
    __tablename__ = "jobs"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    investigation_id: Mapped[str] = mapped_column(String, ForeignKey("investigations.id", ondelete="CASCADE"))
    subject_id: Mapped[str | None] = mapped_column(String, ForeignKey("subjects.id", ondelete="SET NULL"), nullable=True)
    module: Mapped[str] = mapped_column(String)  # module key
    status: Mapped[str] = mapped_column(String, default="queued")  # queued|running|done|error|cancelled
    error: Mapped[str] = mapped_column(Text, default="")
    started_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    result: Mapped[dict] = mapped_column(JSON, default=dict)
    investigation: Mapped[Investigation] = relationship(back_populates="jobs")


class Entity(Base):
    """Normalised entity in the investigation graph."""
    __tablename__ = "entities"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    investigation_id: Mapped[str] = mapped_column(String, ForeignKey("investigations.id", ondelete="CASCADE"))
    type: Mapped[str] = mapped_column(String, index=True)  # domain|ip|email|asn|org|cert|hash|url|username|cve|file
    value: Mapped[str] = mapped_column(String, index=True)
    attributes: Mapped[dict] = mapped_column(JSON, default=dict)
    first_seen: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    confidence: Mapped[float] = mapped_column(Float, default=0.5)
    investigation: Mapped[Investigation] = relationship(back_populates="entities")
    __table_args__ = (Index("ix_entity_unique", "investigation_id", "type", "value", unique=True),)


class Relationship(Base):
    __tablename__ = "relationships"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    investigation_id: Mapped[str] = mapped_column(String, ForeignKey("investigations.id", ondelete="CASCADE"))
    src_id: Mapped[str] = mapped_column(String, ForeignKey("entities.id", ondelete="CASCADE"))
    dst_id: Mapped[str] = mapped_column(String, ForeignKey("entities.id", ondelete="CASCADE"))
    type: Mapped[str] = mapped_column(String)  # resolves_to|hosted_on|member_of|cert_for|owns|...
    source: Mapped[str] = mapped_column(String, default="")
    confidence: Mapped[float] = mapped_column(Float, default=0.5)
    discovered_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    evidence: Mapped[dict] = mapped_column(JSON, default=dict)


class Finding(Base):
    """A single piece of collected intel, bound to source provenance."""
    __tablename__ = "findings"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    investigation_id: Mapped[str] = mapped_column(String, ForeignKey("investigations.id", ondelete="CASCADE"))
    job_id: Mapped[str | None] = mapped_column(String, ForeignKey("jobs.id", ondelete="SET NULL"), nullable=True)
    entity_id: Mapped[str | None] = mapped_column(String, ForeignKey("entities.id", ondelete="SET NULL"), nullable=True)
    module: Mapped[str] = mapped_column(String)
    source: Mapped[str] = mapped_column(String)  # e.g. crt.sh, shodan, dns
    kind: Mapped[str] = mapped_column(String)  # subdomain|whois|mx|...|exif|cve
    data: Mapped[dict] = mapped_column(JSON, default=dict)
    confidence: Mapped[float] = mapped_column(Float, default=0.5)
    collected_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    investigation: Mapped[Investigation] = relationship(back_populates="findings")


class AuditLog(Base):
    __tablename__ = "audit_log"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[str | None] = mapped_column(String, nullable=True)
    action: Mapped[str] = mapped_column(String)
    target: Mapped[str] = mapped_column(String, default="")
    detail: Mapped[dict] = mapped_column(JSON, default=dict)
    at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class IntegrationStatus(Base):
    __tablename__ = "integration_status"
    name: Mapped[str] = mapped_column(String, primary_key=True)
    configured: Mapped[bool] = mapped_column(Boolean, default=False)
    last_ok_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_error: Mapped[str] = mapped_column(Text, default="")
    rate_limit_remaining: Mapped[int | None] = mapped_column(Integer, nullable=True)


class EntityNote(Base):
    """Free-form analyst tags / notes on a graph entity."""
    __tablename__ = "entity_notes"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    entity_id: Mapped[str] = mapped_column(String, ForeignKey("entities.id", ondelete="CASCADE"))
    user_id: Mapped[str | None] = mapped_column(String, nullable=True)
    tags: Mapped[dict] = mapped_column(JSON, default=dict)
    note: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class InvestigationTemplate(Base):
    """Named preset: 'domain workup', 'phishing triage', ..."""
    __tablename__ = "inv_templates"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String, unique=True)
    description: Mapped[str] = mapped_column(Text, default="")
    subject_types: Mapped[dict] = mapped_column(JSON, default=dict)
    modules: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class Schedule(Base):
    """Recurring investigation runs. Interval-based (seconds). Runs on the
    worker tick — see app/worker.py cron_tick."""
    __tablename__ = "schedules"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    investigation_id: Mapped[str] = mapped_column(String, ForeignKey("investigations.id", ondelete="CASCADE"))
    interval_seconds: Mapped[int] = mapped_column(Integer, default=86400)
    modules: Mapped[dict] = mapped_column(JSON, default=dict)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    next_run_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
