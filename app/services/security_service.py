from datetime import datetime

from sqlalchemy import select, func, case

from app.database.database import AsyncSessionLocal
from app.database.models import SecurityEvent, SecurityStats


def normalize_attack_type(attack_type: str):
    """
    Chuyển tên tấn công hiển thị sang enum AttackType trong PostgreSQL.
    """
    attack_map = {
        "Cross-Site Scripting (XSS)": "XSS",
        "SQL Injection": "SQL_INJECTION",
        "Brute Force": "BRUTE_FORCE",
        "API Abuse": "API_ABUSE",
        "Unauthorized Access": "UNAUTHORIZED_ACCESS",
        "Nhiều dấu hiệu tấn công": "SUSPICIOUS_REQUEST"
    }

    return attack_map.get(
        attack_type,
        "SUSPICIOUS_REQUEST"
    )


def get_severity(risk_score: int):
    """
    Phân loại mức độ nghiêm trọng dựa trên Risk Score.
    """
    if risk_score >= 90:
        return "CRITICAL"

    if risk_score >= 60:
        return "HIGH"

    if risk_score >= 30:
        return "MEDIUM"

    return "LOW"


class SecurityService:

    # =========================================================
    # GHI NHẬN REQUEST
    # =========================================================

    async def record_request(
        self,
        ip_address: str,
        method: str,
        path: str
    ):
        """
        Tăng tổng số request trong bảng security_stats.
        """

        async with AsyncSessionLocal() as db:
            result = await db.execute(
                select(SecurityStats).where(
                    SecurityStats.id == 1
                )
            )

            stats = result.scalar_one_or_none()

            # Chưa có record thống kê thì tạo mới
            if stats is None:
                stats = SecurityStats(
                    id=1,
                    total_requests=1,
                    updated_at=datetime.now()
                )

                db.add(stats)

            # Đã có thì tăng request
            else:
                stats.total_requests += 1
                stats.updated_at = datetime.now()

            await db.commit()
            await db.refresh(stats)

            total_requests = stats.total_requests

        print(
            f"[REQUEST #{total_requests}] "
            f"{ip_address} "
            f"{method} "
            f"{path}"
        )


    # =========================================================
    # GHI NHẬN TẤN CÔNG
    # =========================================================

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
        user_id: str | None = None
    ):
        """
        Lưu một Security Event vào PostgreSQL.
        """

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
            created_at=datetime.now()
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


    # =========================================================
    # THỐNG KÊ DASHBOARD
    # =========================================================

    async def get_stats(self):
        """
        Lấy số liệu tổng quan cho Dashboard.
        """

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


            # Tổng số tấn công
            total_attacks = await db.scalar(
                select(
                    func.count(
                        SecurityEvent.id
                    )
                )
            )


            # Tổng số request bị block
            total_blocked = await db.scalar(
                select(
                    func.count(
                        SecurityEvent.id
                    )
                ).where(
                    SecurityEvent.action == "BLOCK"
                )
            )


            # Tổng số sự kiện nghiêm trọng
            total_critical = await db.scalar(
                select(
                    func.count(
                        SecurityEvent.id
                    )
                ).where(
                    SecurityEvent.severity == "CRITICAL"
                )
            )

        return {
            "requests": total_requests,
            "attacks": total_attacks or 0,
            "blocked": total_blocked or 0,
            "critical": total_critical or 0
        }


    # =========================================================
    # DANH SÁCH SECURITY EVENT
    # =========================================================

    async def get_events(
        self,
        limit: int = 200
    ):
        """
        Lấy danh sách Security Event mới nhất.
        """

        async with AsyncSessionLocal() as db:
            result = await db.execute(
                select(SecurityEvent)
                .order_by(
                    SecurityEvent.created_at.desc()
                )
                .limit(limit)
            )

            records = result.scalars().all()

        events = []

        for item in records:
            events.append({
                "id": item.id,

                "time": (
                    item.created_at.strftime(
                        "%d/%m/%Y %H:%M:%S"
                    )
                    if item.created_at
                    else ""
                ),

                "ip_address": item.ip_address,

                "client_key": item.client_key,

                "user_id": item.user_id,

                "user_agent": item.user_agent,

                "method": item.method,

                "path": item.path,

                "attack_type": (
                    self.get_attack_display_name(
                        item.attack_type
                    )
                ),

                "attack_type_code": (
                    item.attack_type
                ),

                "severity": item.severity,

                "risk_score": item.risk_score,

                "action": item.action,

                "reason": item.reason
            })

        return events


    # =========================================================
    # THỐNG KÊ THEO LOẠI TẤN CÔNG
    # =========================================================

    async def get_attack_statistics(self):
        """
        Thống kê số lượng, số lần block
        và Risk Score trung bình theo loại tấn công.
        """

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
                                1
                            ),
                            else_=0
                        )
                    ).label(
                        "blocked"
                    ),

                    func.avg(
                        SecurityEvent.risk_score
                    ).label(
                        "average_risk"
                    )
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
            statistics.append({
                "attack_type": (
                    self.get_attack_display_name(
                        row.attack_type
                    )
                ),

                "attack_type_code": (
                    row.attack_type
                ),

                "count": row.count,

                "blocked": row.blocked or 0,

                "average_risk": round(
                    float(
                        row.average_risk or 0
                    ),
                    1
                )
            })

        return statistics


    # =========================================================
    # CHUYỂN ENUM SANG TÊN HIỂN THỊ
    # =========================================================

    def get_attack_display_name(
        self,
        attack_type: str
    ):
        """
        Chuyển enum PostgreSQL sang tên tiếng Việt / dễ đọc.
        """

        attack_names = {
            "SQL_INJECTION": "SQL Injection",
            "XSS": "Cross-Site Scripting (XSS)",
            "BRUTE_FORCE": "Brute Force",
            "API_ABUSE": "API Abuse",
            "UNAUTHORIZED_ACCESS": "Unauthorized Access",
            "SUSPICIOUS_REQUEST": "Yêu cầu đáng ngờ"
        }

        return attack_names.get(
            attack_type,
            attack_type
        )


security_service = SecurityService()