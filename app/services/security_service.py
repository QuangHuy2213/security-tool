from datetime import datetime, timezone, timedelta

from sqlalchemy import select, func, case, or_

from app.database.database import AsyncSessionLocal
from app.database.models import (
    SecurityEvent,
    SecurityStats,
    ClientViolation,
    BlockedIp,
)


# =========================================================
# TIMEZONE
# =========================================================

VIETNAM_TZ = timezone(timedelta(hours=7))


def utc_now():
    """
    Thời gian UTC dạng naive để tương thích
    với các cột DateTime hiện tại trong PostgreSQL.
    """
    return datetime.now(timezone.utc).replace(tzinfo=None)


def format_datetime(value):
    """
    Database lưu UTC.
    Dashboard hiển thị theo giờ Việt Nam UTC+7.
    """
    if not value:
        return None

    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    else:
        value = value.astimezone(timezone.utc)

    return value.astimezone(VIETNAM_TZ).strftime(
        "%d/%m/%Y %H:%M:%S"
    )


def get_remaining_seconds(expires_at):
    if not expires_at:
        return None

    if expires_at.tzinfo is None:
        now = utc_now()
    else:
        now = datetime.now(timezone.utc)

    remaining = int(
        (expires_at - now).total_seconds()
    )

    return max(remaining, 0)


def format_remaining_time(seconds):
    if seconds is None:
        return "Không giới hạn"

    if seconds <= 0:
        return "Đã hết hạn"

    hours = seconds // 3600
    minutes = (seconds % 3600) // 60
    secs = seconds % 60

    if hours > 0:
        return f"{hours} giờ {minutes} phút"

    if minutes > 0:
        return f"{minutes} phút {secs} giây"

    return f"{secs} giây"


# =========================================================
# ATTACK TYPE
# =========================================================

def normalize_attack_type(attack_type: str):
    attack_map = {
        "Cross-Site Scripting (XSS)": "XSS",
        "SQL Injection": "SQL_INJECTION",
        "Brute Force": "BRUTE_FORCE",
        "API Abuse": "API_ABUSE",
        "Unauthorized Access": "UNAUTHORIZED_ACCESS",
        "Nhiều dấu hiệu tấn công": "SUSPICIOUS_REQUEST",
    }

    return attack_map.get(
        attack_type,
        "SUSPICIOUS_REQUEST",
    )


def get_severity(risk_score: int):
    if risk_score >= 90:
        return "CRITICAL"

    if risk_score >= 60:
        return "HIGH"

    if risk_score >= 30:
        return "MEDIUM"

    return "LOW"


# =========================================================
# SECURITY SERVICE
# =========================================================

class SecurityService:

    # =====================================================
    # RECORD REQUEST
    # =====================================================

    async def record_request(
        self,
        ip_address: str,
        method: str,
        path: str,
    ):
        async with AsyncSessionLocal() as db:
            result = await db.execute(
                select(SecurityStats).where(
                    SecurityStats.id == 1
                )
            )

            stats = result.scalar_one_or_none()

            if stats is None:
                stats = SecurityStats(
                    id=1,
                    total_requests=1,
                    updated_at=utc_now(),
                )
                db.add(stats)
            else:
                stats.total_requests += 1
                stats.updated_at = utc_now()

            await db.commit()
            await db.refresh(stats)

            total_requests = stats.total_requests

        print(
            f"[REQUEST #{total_requests}] "
            f"{ip_address} {method} {path}"
        )

    # =====================================================
    # RECORD ATTACK
    # =====================================================

    async def record_attack(
        self,
        ip_address: str,
        client_key: str,
        user_agent: str,
        method: str,
        path: str,
        attack_type: str,
        risk_score: int,
        action: str,
        reason: str | None = None,
        user_id: str | None = None,
    ):
        normalized_attack_type = normalize_attack_type(
            attack_type
        )

        severity = get_severity(
            risk_score
        )

        event = SecurityEvent(
            ip_address=ip_address,
            client_key=client_key,
            user_id=user_id,
            user_agent=user_agent,
            method=method,
            path=path,
            attack_type=normalized_attack_type,
            severity=severity,
            risk_score=risk_score,
            action=action,
            reason=reason,

            # Luôn lưu UTC
            created_at=utc_now(),
        )

        async with AsyncSessionLocal() as db:
            db.add(event)

            await db.commit()
            await db.refresh(event)

        print(
            f"[PHÁT HIỆN] "
            f"{attack_type} "
            f"| IP={ip_address} "
            f"| Risk={risk_score} "
            f"| Severity={severity} "
            f"| Action={action}"
        )

        return event

    # =====================================================
    # DASHBOARD STATS
    # =====================================================

    async def get_stats(self):
        now = utc_now()

        async with AsyncSessionLocal() as db:

            # Tổng request
            request_result = await db.execute(
                select(SecurityStats).where(
                    SecurityStats.id == 1
                )
            )

            request_stats = (
                request_result.scalar_one_or_none()
            )

            total_requests = (
                request_stats.total_requests
                if request_stats
                else 0
            )

            # Tổng Security Event
            total_attacks = (
                await db.scalar(
                    select(
                        func.count(
                            SecurityEvent.id
                        )
                    )
                )
            ) or 0

            # Tổng event BLOCK
            total_blocked = (
                await db.scalar(
                    select(
                        func.count(
                            SecurityEvent.id
                        )
                    ).where(
                        SecurityEvent.action
                        == "BLOCK"
                    )
                )
            ) or 0

            # Tổng CRITICAL
            total_critical = (
                await db.scalar(
                    select(
                        func.count(
                            SecurityEvent.id
                        )
                    ).where(
                        SecurityEvent.severity
                        == "CRITICAL"
                    )
                )
            ) or 0

            # Client/IP còn đang block
            active_blocks = (
                await db.scalar(
                    select(
                        func.count(
                            BlockedIp.id
                        )
                    ).where(
                        BlockedIp.is_active.is_(True),
                        or_(
                            BlockedIp.expires_at.is_(None),
                            BlockedIp.expires_at > now,
                        ),
                    )
                )
            ) or 0

            # Count từng attack type
            type_result = await db.execute(
                select(
                    SecurityEvent.attack_type,
                    func.count(
                        SecurityEvent.id
                    ),
                ).group_by(
                    SecurityEvent.attack_type
                )
            )

            rows = type_result.all()

        attack_counts = {
            "SQL_INJECTION": 0,
            "XSS": 0,
            "API_ABUSE": 0,
            "BRUTE_FORCE": 0,
            "UNAUTHORIZED_ACCESS": 0,
            "SUSPICIOUS_REQUEST": 0,
        }

        for attack_type, count in rows:
            code = getattr(
                attack_type,
                "value",
                attack_type,
            )

            attack_counts[str(code)] = count

        return {
            "requests": total_requests,
            "attacks": total_attacks,
            "blocked": total_blocked,
            "critical": total_critical,
            "active_blocks": active_blocks,
            "sql_injection": attack_counts.get(
                "SQL_INJECTION",
                0,
            ),
            "xss": attack_counts.get(
                "XSS",
                0,
            ),
            "api_abuse": attack_counts.get(
                "API_ABUSE",
                0,
            ),
            "brute_force": attack_counts.get(
                "BRUTE_FORCE",
                0,
            ),
            "suspicious": attack_counts.get(
                "SUSPICIOUS_REQUEST",
                0,
            ),
        }

    # =====================================================
    # SECURITY EVENTS
    # =====================================================

    async def get_events(
        self,
        limit: int = 200,
    ):
        now = utc_now()

        async with AsyncSessionLocal() as db:

            # =================================================
            # QUAN TRỌNG:
            #
            # Không sort bằng created_at vì dữ liệu cũ có thể
            # được tạo bởi local UTC+7 và Render UTC.
            #
            # ID lớn hơn = event được insert sau.
            # =================================================

            result = await db.execute(
                select(SecurityEvent)
                .order_by(
                    SecurityEvent.id.desc()
                )
                .limit(limit)
            )

            records = (
                result.scalars().all()
            )

            client_keys = list({
                item.client_key
                for item in records
                if item.client_key
            })

            # =================================================
            # CLIENT VIOLATION
            # =================================================

            violation_map = {}

            if client_keys:
                violation_result = await db.execute(
                    select(ClientViolation).where(
                        ClientViolation.client_key.in_(
                            client_keys
                        )
                    )
                )

                violations = (
                    violation_result.scalars().all()
                )

                violation_map = {
                    item.client_key: item
                    for item in violations
                }

            # =================================================
            # ACTIVE BLOCK
            # =================================================

            blocked_map = {}

            if client_keys:
                blocked_result = await db.execute(
                    select(BlockedIp)
                    .where(
                        BlockedIp.client_key.in_(
                            client_keys
                        ),
                        BlockedIp.is_active.is_(True),
                        or_(
                            BlockedIp.expires_at.is_(None),
                            BlockedIp.expires_at > now,
                        ),
                    )

                    # Dùng ID để tránh timestamp cũ lệch timezone
                    .order_by(
                        BlockedIp.id.desc()
                    )
                )

                blocked_records = (
                    blocked_result.scalars().all()
                )

                for blocked in blocked_records:
                    if (
                        blocked.client_key
                        not in blocked_map
                    ):
                        blocked_map[
                            blocked.client_key
                        ] = blocked

        events = []

        for item in records:
            client_key = item.client_key

            violation = violation_map.get(
                client_key
            )

            blocked = blocked_map.get(
                client_key
            )

            remaining_seconds = (
                get_remaining_seconds(
                    blocked.expires_at
                )
                if blocked
                else None
            )

            attack_type_code = getattr(
                item.attack_type,
                "value",
                item.attack_type,
            )

            severity = getattr(
                item.severity,
                "value",
                item.severity,
            )

            action = getattr(
                item.action,
                "value",
                item.action,
            )

            events.append({
                "id": item.id,

                # Thời gian hiển thị GMT+7
                "time": format_datetime(
                    item.created_at
                ),

                "created_at": item.created_at,

                # Client
                "ip_address": item.ip_address,
                "client_key": client_key,

                "client_key_short": (
                    f"{client_key[:12]}..."
                    if client_key
                    else "-"
                ),

                "user_id": item.user_id,
                "user_agent": item.user_agent,

                # Request
                "method": item.method,
                "path": item.path,

                # Attack
                "attack_type": (
                    self.get_attack_display_name(
                        attack_type_code
                    )
                ),

                "attack_type_code": (
                    attack_type_code
                ),

                "severity": severity,
                "risk_score": item.risk_score,
                "action": action,
                "reason": item.reason,

                # Violation
                "violation_count": (
                    violation.violation_count
                    if violation
                    else 0
                ),

                "total_risk": (
                    violation.total_risk
                    if violation
                    else 0
                ),

                "first_violation_at": (
                    format_datetime(
                        violation.first_violation_at
                    )
                    if violation
                    else None
                ),

                "last_violation_at": (
                    format_datetime(
                        violation.last_violation_at
                    )
                    if violation
                    else None
                ),

                # Block
                "is_blocked": (
                    blocked is not None
                ),

                "block_reason": (
                    blocked.reason
                    if blocked
                    else None
                ),

                "blocked_at": (
                    format_datetime(
                        blocked.blocked_at
                    )
                    if blocked
                    else None
                ),

                "expires_at": (
                    format_datetime(
                        blocked.expires_at
                    )
                    if blocked
                    else None
                ),

                "remaining_seconds": (
                    remaining_seconds
                ),

                "remaining_text": (
                    format_remaining_time(
                        remaining_seconds
                    )
                    if blocked
                    else "-"
                ),
            })

        return events

    # =====================================================
    # ATTACK STATISTICS
    # =====================================================

    async def get_attack_statistics(
        self,
    ):
        async with AsyncSessionLocal() as db:
            result = await db.execute(
                select(
                    SecurityEvent.attack_type,

                    func.count(
                        SecurityEvent.id
                    ).label(
                        "count"
                    ),

                    func.sum(
                        case(
                            (
                                SecurityEvent.action
                                == "BLOCK",
                                1,
                            ),
                            else_=0,
                        )
                    ).label(
                        "blocked"
                    ),

                    func.avg(
                        SecurityEvent.risk_score
                    ).label(
                        "average_risk"
                    ),

                    func.max(
                        SecurityEvent.risk_score
                    ).label(
                        "max_risk"
                    ),
                )
                .group_by(
                    SecurityEvent.attack_type
                )
                .order_by(
                    func.count(
                        SecurityEvent.id
                    ).desc()
                )
            )

            rows = result.all()

        statistics = []

        for row in rows:
            attack_type_code = getattr(
                row.attack_type,
                "value",
                row.attack_type,
            )

            statistics.append({
                "attack_type": (
                    self.get_attack_display_name(
                        attack_type_code
                    )
                ),

                "attack_type_code": (
                    attack_type_code
                ),

                "count": row.count,

                "blocked": (
                    row.blocked or 0
                ),

                "average_risk": round(
                    float(
                        row.average_risk or 0
                    ),
                    1,
                ),

                "max_risk": (
                    row.max_risk or 0
                ),
            })

        return statistics

    # =====================================================
    # ATTACK DISPLAY NAME
    # =====================================================

    def get_attack_display_name(
        self,
        attack_type: str,
    ):
        code = getattr(
            attack_type,
            "value",
            attack_type,
        )

        attack_names = {
            "SQL_INJECTION":
                "SQL Injection",

            "XSS":
                "Cross-Site Scripting (XSS)",

            "BRUTE_FORCE":
                "Brute Force",

            "API_ABUSE":
                "API Abuse",

            "UNAUTHORIZED_ACCESS":
                "Unauthorized Access",

            "SUSPICIOUS_REQUEST":
                "Yêu cầu đáng ngờ",
        }

        return attack_names.get(
            str(code),
            str(code),
        )


security_service = SecurityService()