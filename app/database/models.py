from datetime import datetime

from sqlalchemy import (
    String,
    Integer,
    Boolean,
    DateTime,
    Text
)
from sqlalchemy.dialects.postgresql import ENUM
from sqlalchemy.orm import Mapped, mapped_column

from app.database.database import Base


attack_type_enum = ENUM(
    "SQL_INJECTION",
    "XSS",
    "BRUTE_FORCE",
    "API_ABUSE",
    "UNAUTHORIZED_ACCESS",
    "SUSPICIOUS_REQUEST",
    name="AttackType",
    create_type=False
)

security_action_enum = ENUM(
    "ALLOW",
    "ALERT",
    "BLOCK",
    name="SecurityAction",
    create_type=False
)

security_severity_enum = ENUM(
    "LOW",
    "MEDIUM",
    "HIGH",
    "CRITICAL",
    name="SecuritySeverity",
    create_type=False
)


class SecurityEvent(Base):
    __tablename__ = "security_events"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True
    )

    ip_address: Mapped[str | None] = mapped_column(
        "ipAddress",
        String(64),
        nullable=True
    )

    client_key: Mapped[str | None] = mapped_column(
        "clientKey",
        String(128),
        nullable=True
    )

    user_id: Mapped[str | None] = mapped_column(
        "userId",
        String,
        nullable=True
    )

    user_agent: Mapped[str | None] = mapped_column(
        "userAgent",
        Text,
        nullable=True
    )

    method: Mapped[str] = mapped_column(
        String(10)
    )

    path: Mapped[str] = mapped_column(
        Text
    )

    attack_type: Mapped[str] = mapped_column(
        "attackType",
        attack_type_enum
    )

    severity: Mapped[str] = mapped_column(
        security_severity_enum
    )

    risk_score: Mapped[int] = mapped_column(
        "riskScore",
        Integer
    )

    action: Mapped[str] = mapped_column(
        security_action_enum
    )

    reason: Mapped[str | None] = mapped_column(
        Text,
        nullable=True
    )

    created_at: Mapped[datetime] = mapped_column(
        "createdAt",
        DateTime
    )


class ClientViolation(Base):
    __tablename__ = "security_client_violations"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True
    )

    client_key: Mapped[str] = mapped_column(
        "clientKey",
        String(128),
        unique=True
    )

    ip_address: Mapped[str | None] = mapped_column(
        "ipAddress",
        String(64),
        nullable=True
    )

    violation_count: Mapped[int] = mapped_column(
        "violationCount",
        Integer,
        default=0
    )

    total_risk: Mapped[int] = mapped_column(
        "totalRisk",
        Integer,
        default=0
    )

    last_attack_type: Mapped[str | None] = mapped_column(
        "lastAttackType",
        attack_type_enum,
        nullable=True
    )

    first_violation_at: Mapped[datetime] = mapped_column(
        "firstViolationAt",
        DateTime
    )

    last_violation_at: Mapped[datetime] = mapped_column(
        "lastViolationAt",
        DateTime
    )


class BlockedIp(Base):
    __tablename__ = "security_blocked_ips"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True
    )

    ip_address: Mapped[str | None] = mapped_column(
        "ipAddress",
        String(64),
        nullable=True
    )

    client_key: Mapped[str | None] = mapped_column(
        "clientKey",
        String(128),
        nullable=True
    )

    reason: Mapped[str] = mapped_column(
        Text
    )

    violation_count: Mapped[int] = mapped_column(
        "violationCount",
        Integer,
        default=0
    )

    total_risk: Mapped[int] = mapped_column(
        "totalRisk",
        Integer,
        default=0
    )

    is_active: Mapped[bool] = mapped_column(
        "isActive",
        Boolean,
        default=True
    )

    blocked_at: Mapped[datetime] = mapped_column(
        "blockedAt",
        DateTime
    )

    expires_at: Mapped[datetime | None] = mapped_column(
        "expiresAt",
        DateTime,
        nullable=True
    )
    
class SecurityStats(Base):
    __tablename__ = "security_stats"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True
    )

    total_requests: Mapped[int] = mapped_column(
        "totalRequests",
        Integer,
        default=0
    )

    updated_at: Mapped[datetime] = mapped_column(
        "updatedAt",
        DateTime
    )
class SecurityRateLimit(Base):
    __tablename__ = "security_rate_limits"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True
    )

    client_key: Mapped[str] = mapped_column(
        "clientKey",
        String(128)
    )

    endpoint: Mapped[str] = mapped_column(
        String(255)
    )

    request_count: Mapped[int] = mapped_column(
        "requestCount",
        Integer,
        default=0
    )

    window_start: Mapped[datetime] = mapped_column(
        "windowStart",
        DateTime
    )

    updated_at: Mapped[datetime] = mapped_column(
        "updatedAt",
        DateTime
    )
class SecurityLoginAttempt(Base):
    __tablename__ = "security_login_attempts"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True
    )

    client_key: Mapped[str] = mapped_column(
        "clientKey",
        String(128)
    )

    identifier_hash: Mapped[str] = mapped_column(
        "identifierHash",
        String(64)
    )

    endpoint: Mapped[str] = mapped_column(
        String(255)
    )

    failed_count: Mapped[int] = mapped_column(
        "failedCount",
        Integer,
        default=0
    )

    window_start: Mapped[datetime] = mapped_column(
        "windowStart",
        DateTime
    )

    blocked_until: Mapped[datetime | None] = mapped_column(
        "blockedUntil",
        DateTime,
        nullable=True
    )

    updated_at: Mapped[datetime] = mapped_column(
        "updatedAt",
        DateTime
    )