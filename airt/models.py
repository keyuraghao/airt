"""ORM models. Everything the platform knows is persisted here."""
from __future__ import annotations

import enum
import uuid
from datetime import UTC, datetime

from sqlalchemy import JSON, Boolean, DateTime, Float, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .db import Base


def utcnow() -> datetime:
    return datetime.now(UTC)


def new_id(prefix: str = "") -> str:
    return f"{prefix}{uuid.uuid4().hex}"


class TicketStatus(str, enum.Enum):
    PENDING = "PENDING"          # waiting for a human decision
    APPROVED = "APPROVED"        # human (or policy) approved, not yet forwarded
    DENIED = "DENIED"            # blocked; nothing was sent upstream
    EXPIRED = "EXPIRED"          # no decision before the timeout; nothing was sent upstream
    FORWARDING = "FORWARDING"    # request in flight to the upstream
    COMPLETED = "COMPLETED"      # upstream answered and the response was relayed
    FAILED = "FAILED"            # upstream / network error after approval


class RiskLevel(str, enum.Enum):
    NONE = "NONE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Reviewer(Base):
    __tablename__ = "reviewers"
    id: Mapped[str] = mapped_column(String(40), primary_key=True, default=lambda: new_id("usr_"))
    username: Mapped[str] = mapped_column(String(80), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(20), default="reviewer")  # admin | reviewer | viewer
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class Agent(Base):
    """A registered client: a frontend app, an autonomous agent, a red-team runner..."""

    __tablename__ = "agents"
    id: Mapped[str] = mapped_column(String(40), primary_key=True, default=lambda: new_id("agt_"))
    name: Mapped[str] = mapped_column(String(120), unique=True, index=True)
    description: Mapped[str] = mapped_column(Text, default="")
    owner: Mapped[str] = mapped_column(String(120), default="")
    tags: Mapped[list] = mapped_column(JSON, default=list)
    api_key_hash: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    api_key_prefix: Mapped[str] = mapped_column(String(16))
    # upstream / backend the agent is allowed to reach through the gateway
    upstream_provider: Mapped[str] = mapped_column(String(30), default="openai")  # openai | anthropic | custom
    upstream_base_url: Mapped[str] = mapped_column(String(500), default="https://api.openai.com/v1")
    upstream_api_key_encrypted: Mapped[str | None] = mapped_column(Text, nullable=True)
    upstream_auth_header: Mapped[str] = mapped_column(String(80), default="")  # custom provider header name
    upstream_extra_headers: Mapped[dict] = mapped_column(JSON, default=dict)
    # policy
    require_approval: Mapped[bool] = mapped_column(Boolean, default=True)
    auto_approve_below_risk: Mapped[int] = mapped_column(Integer, default=0)   # 0 disables auto approval
    auto_deny_at_risk: Mapped[int] = mapped_column(Integer, default=90)
    auto_deny_patterns: Mapped[list] = mapped_column(JSON, default=list)      # regexes matched against prompt text
    allowed_paths: Mapped[list] = mapped_column(JSON, default=list)           # glob patterns; empty = all
    allowed_models: Mapped[list] = mapped_column(JSON, default=list)          # empty = all
    rate_limit_per_minute: Mapped[int] = mapped_column(Integer, default=0)    # 0 = unlimited
    inject_canary: Mapped[bool] = mapped_column(Boolean, default=False)       # Rebuff style canary word in every system prompt
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    # stats
    request_count: Mapped[int] = mapped_column(Integer, default=0)
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    tickets: Mapped[list[Ticket]] = relationship(back_populates="agent", lazy="noload")


class ScanToken(Base):
    """Short-lived credential minted for external scanners (garak, promptfoo, PyRIT) to act as an agent."""

    __tablename__ = "scan_tokens"
    id: Mapped[str] = mapped_column(String(40), primary_key=True, default=lambda: new_id("scn_"))
    agent_id: Mapped[str] = mapped_column(ForeignKey("agents.id"), index=True)
    token_hash: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    purpose: Mapped[str] = mapped_column(String(80), default="")
    campaign_id: Mapped[str | None] = mapped_column(String(40), nullable=True, index=True)
    created_by: Mapped[str] = mapped_column(String(80), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)


class Ticket(Base):
    """One intercepted outbound request."""

    __tablename__ = "tickets"
    id: Mapped[str] = mapped_column(String(40), primary_key=True, default=lambda: new_id("tkt_"))
    number: Mapped[int] = mapped_column(Integer, autoincrement=True, unique=True, nullable=True)
    agent_id: Mapped[str] = mapped_column(ForeignKey("agents.id"), index=True)
    status: Mapped[str] = mapped_column(String(20), default=TicketStatus.PENDING.value, index=True)
    source: Mapped[str] = mapped_column(String(20), default="gateway")  # gateway | mitm | sdk | redteam
    correlation_id: Mapped[str] = mapped_column(String(80), default=lambda: new_id("corr_"), index=True)
    client_ip: Mapped[str] = mapped_column(String(64), default="")
    user_agent: Mapped[str] = mapped_column(String(300), default="")

    method: Mapped[str] = mapped_column(String(10))
    path: Mapped[str] = mapped_column(String(500))
    upstream_url: Mapped[str] = mapped_column(String(800), default="")
    request_headers: Mapped[dict] = mapped_column(JSON, default=dict)   # redacted
    request_body: Mapped[str] = mapped_column(Text, default="")        # raw (truncated)
    request_json: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    normalized: Mapped[dict] = mapped_column(JSON, default=dict)        # provider/model/messages/tools/stream
    prompt_preview: Mapped[str] = mapped_column(String(500), default="")
    model: Mapped[str] = mapped_column(String(120), default="", index=True)
    is_stream: Mapped[bool] = mapped_column(Boolean, default=False)

    risk_score: Mapped[int] = mapped_column(Integer, default=0, index=True)
    risk_level: Mapped[str] = mapped_column(String(10), default=RiskLevel.NONE.value)
    findings: Mapped[list] = mapped_column(JSON, default=list)
    analysis_ms: Mapped[float] = mapped_column(Float, default=0.0)
    policy_decision: Mapped[dict] = mapped_column(JSON, default=dict)

    decided_by: Mapped[str | None] = mapped_column(String(80), nullable=True)
    decision_note: Mapped[str] = mapped_column(Text, default="")
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    forwarded_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    response_status: Mapped[int | None] = mapped_column(Integer, nullable=True)
    response_headers: Mapped[dict] = mapped_column(JSON, default=dict)
    response_body: Mapped[str] = mapped_column(Text, default="")
    response_preview: Mapped[str] = mapped_column(String(500), default="")
    response_findings: Mapped[list] = mapped_column(JSON, default=list)
    latency_ms: Mapped[float | None] = mapped_column(Float, nullable=True)
    error: Mapped[str] = mapped_column(Text, default="")

    campaign_id: Mapped[str | None] = mapped_column(String(40), nullable=True, index=True)
    probe_id: Mapped[str | None] = mapped_column(String(80), nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    agent: Mapped[Agent] = relationship(back_populates="tickets", lazy="joined")
    events: Mapped[list[TicketEvent]] = relationship(back_populates="ticket", lazy="noload", cascade="all, delete-orphan")


Index("ix_tickets_agent_status", Ticket.agent_id, Ticket.status)


class TicketEvent(Base):
    __tablename__ = "ticket_events"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ticket_id: Mapped[str] = mapped_column(ForeignKey("tickets.id", ondelete="CASCADE"), index=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    event_type: Mapped[str] = mapped_column(String(40))
    actor: Mapped[str] = mapped_column(String(80), default="system")
    detail: Mapped[dict] = mapped_column(JSON, default=dict)

    ticket: Mapped[Ticket] = relationship(back_populates="events")


class AgentEvent(Base):
    """Per-agent activity log (durable copy of what also goes to logs/agents/<id>.jsonl)."""

    __tablename__ = "agent_events"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    agent_id: Mapped[str] = mapped_column(String(40), index=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    level: Mapped[str] = mapped_column(String(10), default="INFO")
    event: Mapped[str] = mapped_column(String(80))
    ticket_id: Mapped[str | None] = mapped_column(String(40), nullable=True, index=True)
    correlation_id: Mapped[str | None] = mapped_column(String(80), nullable=True)
    detail: Mapped[dict] = mapped_column(JSON, default=dict)


class AuditEntry(Base):
    """Tamper-evident, hash-chained audit log of every privileged action."""

    __tablename__ = "audit_log"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    actor: Mapped[str] = mapped_column(String(80))
    action: Mapped[str] = mapped_column(String(60), index=True)
    target_type: Mapped[str] = mapped_column(String(40))
    target_id: Mapped[str] = mapped_column(String(80), index=True)
    detail: Mapped[dict] = mapped_column(JSON, default=dict)
    prev_hash: Mapped[str] = mapped_column(String(64), default="0" * 64)
    hash: Mapped[str] = mapped_column(String(64), unique=True)


class CampaignStatus(str, enum.Enum):
    CREATED = "CREATED"
    RUNNING = "RUNNING"
    PAUSED = "PAUSED"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class Campaign(Base):
    """A red-team run against one target through one agent identity."""

    __tablename__ = "campaigns"
    id: Mapped[str] = mapped_column(String(40), primary_key=True, default=lambda: new_id("cmp_"))
    name: Mapped[str] = mapped_column(String(160))
    agent_id: Mapped[str] = mapped_column(ForeignKey("agents.id"), index=True)
    target_model: Mapped[str] = mapped_column(String(120), default="")
    status: Mapped[str] = mapped_column(String(20), default=CampaignStatus.CREATED.value, index=True)
    config: Mapped[dict] = mapped_column(JSON, default=dict)      # categories, techniques, sampling, system prompt...
    summary: Mapped[dict] = mapped_column(JSON, default=dict)     # aggregated results
    total_probes: Mapped[int] = mapped_column(Integer, default=0)
    completed_probes: Mapped[int] = mapped_column(Integer, default=0)
    created_by: Mapped[str] = mapped_column(String(80), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    error: Mapped[str] = mapped_column(Text, default="")


class ProbeResult(Base):
    __tablename__ = "probe_results"
    id: Mapped[str] = mapped_column(String(40), primary_key=True, default=lambda: new_id("prb_"))
    campaign_id: Mapped[str] = mapped_column(ForeignKey("campaigns.id", ondelete="CASCADE"), index=True)
    probe_id: Mapped[str] = mapped_column(String(120), index=True)
    category: Mapped[str] = mapped_column(String(60), index=True)
    technique: Mapped[str] = mapped_column(String(60), default="")
    severity: Mapped[str] = mapped_column(String(10), default="MEDIUM")
    prompt: Mapped[str] = mapped_column(Text)
    messages: Mapped[list] = mapped_column(JSON, default=list)
    response: Mapped[str] = mapped_column(Text, default="")
    verdict: Mapped[str] = mapped_column(String(20), default="PENDING")  # VULNERABLE | RESISTED | BLOCKED | ERROR | PENDING | INCONCLUSIVE
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    evidence: Mapped[dict] = mapped_column(JSON, default=dict)
    ticket_id: Mapped[str | None] = mapped_column(String(40), nullable=True)
    latency_ms: Mapped[float | None] = mapped_column(Float, nullable=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AppSetting(Base):
    """Runtime configuration overrides edited from the Settings UI (take precedence over env and .env)."""

    __tablename__ = "app_settings"
    namespace: Mapped[str] = mapped_column(String(40), primary_key=True, default="core")
    key: Mapped[str] = mapped_column(String(120), primary_key=True)
    value: Mapped[dict] = mapped_column(JSON, default=dict)  # {"v": <json value>}
    updated_by: Mapped[str] = mapped_column(String(80), default="")
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)
