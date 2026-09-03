from datetime import datetime, timedelta

from sqlalchemy import select, or_

from app.core.config import settings
from app.database.database import AsyncSessionLocal
from app.database.models import ClientViolation, BlockedIp


def normalize_attack_type(attack_type: str):
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


class IPBlocker:
    async def register_violation(
        self,
        ip_address: str,
        client_key: str,
        risk_score: int,
        attack_type: str
    ):
        now = datetime.now()

        # Chuẩn hóa loại tấn công trước khi lưu PostgreSQL
        normalized_attack_type = normalize_attack_type(
            attack_type
        )

        async with AsyncSessionLocal() as db:
            result = await db.execute(
                select(ClientViolation).where(
                    ClientViolation.client_key == client_key
                )
            )

            violation = result.scalar_one_or_none()

            # Chưa có client này -> tạo mới
            if violation is None:
                violation = ClientViolation(
                    client_key=client_key,
                    ip_address=ip_address,
                    violation_count=1,
                    total_risk=risk_score,
                    last_attack_type=normalized_attack_type,
                    first_violation_at=now,
                    last_violation_at=now
                )

                db.add(violation)

            # Đã tồn tại -> tăng số lần vi phạm
            else:
                violation.ip_address = ip_address
                violation.violation_count += 1
                violation.total_risk += risk_score
                violation.last_attack_type = normalized_attack_type
                violation.last_violation_at = now

            await db.commit()
            await db.refresh(violation)

            count = violation.violation_count
            total_risk = violation.total_risk

        print(
            f"[VI PHẠM] "
            f"IP={ip_address} "
            f"| Client={client_key[:12]} "
            f"| Lần={count} "
            f"| Risk={risk_score} "
            f"| Attack={normalized_attack_type}"
        )

        # Điều kiện khóa
        should_block = (
            risk_score >= settings.IMMEDIATE_BLOCK_SCORE
            or count >= settings.MAX_VIOLATIONS
        )

        if should_block:
            reason = (
                f"Phát hiện {attack_type}. "
                f"Số lần vi phạm: {count}. "
                f"Risk Score gần nhất: {risk_score}/100."
            )

            await self.block_ip(
                ip_address=ip_address,
                client_key=client_key,
                reason=reason,
                violation_count=count,
                total_risk=total_risk
            )

        return {
            "violation_count": count,
            "blocked": should_block
        }


    async def block_ip(
        self,
        ip_address: str,
        client_key: str,
        reason: str,
        violation_count: int,
        total_risk: int
    ):
        now = datetime.now()

        expires_at = now + timedelta(
            seconds=settings.BLOCK_DURATION_SECONDS
        )

        async with AsyncSessionLocal() as db:
            result = await db.execute(
                select(BlockedIp).where(
                    BlockedIp.client_key == client_key,
                    BlockedIp.is_active.is_(True)
                )
            )

            blocked = result.scalar_one_or_none()

            # Chưa có trong danh sách block
            if blocked is None:
                blocked = BlockedIp(
                    ip_address=ip_address,
                    client_key=client_key,
                    reason=reason,
                    violation_count=violation_count,
                    total_risk=total_risk,
                    is_active=True,
                    blocked_at=now,
                    expires_at=expires_at
                )

                db.add(blocked)

            # Đã có -> cập nhật
            else:
                blocked.ip_address = ip_address
                blocked.reason = reason
                blocked.violation_count = violation_count
                blocked.total_risk = total_risk
                blocked.is_active = True
                blocked.blocked_at = now
                blocked.expires_at = expires_at

            await db.commit()

        print(
            f"[KHÓA CLIENT] "
            f"IP={ip_address} "
            f"| Client={client_key[:12]} "
            f"| Hết hạn={expires_at}"
        )


    async def is_blocked(
        self,
        ip_address: str,
        client_key: str
    ):
        async with AsyncSessionLocal() as db:
            result = await db.execute(
                select(BlockedIp).where(
                    BlockedIp.is_active.is_(True),
                    or_(
                        BlockedIp.client_key == client_key,
                        BlockedIp.ip_address == ip_address
                    )
                )
            )

            blocked = result.scalars().first()

            if blocked is None:
                return None

            now = datetime.now()

            # Hết thời gian khóa
            if (
                blocked.expires_at is not None
                and blocked.expires_at <= now
            ):
                blocked.is_active = False

                await db.commit()

                print(
                    f"[HẾT HẠN BLOCK] "
                    f"IP={blocked.ip_address}"
                )

                return None

            return {
                "blocked": True,
                "reason": blocked.reason
            }


    async def unblock_ip(
        self,
        ip_address: str
    ):
        async with AsyncSessionLocal() as db:
            result = await db.execute(
                select(BlockedIp).where(
                    BlockedIp.ip_address == ip_address,
                    BlockedIp.is_active.is_(True)
                )
            )

            records = result.scalars().all()

            if not records:
                return False

            client_keys = []

            # Tắt trạng thái block
            for record in records:
                record.is_active = False

                if record.client_key:
                    client_keys.append(
                        record.client_key
                    )

            # Reset violation của client
            for client_key in client_keys:
                violation_result = await db.execute(
                    select(ClientViolation).where(
                        ClientViolation.client_key
                        == client_key
                    )
                )

                violation = (
                    violation_result
                    .scalar_one_or_none()
                )

                if violation:
                    violation.violation_count = 0
                    violation.total_risk = 0
                    violation.last_attack_type = None
                    violation.last_violation_at = datetime.now()

            await db.commit()

        print(
            f"[BỎ CHẶN] IP={ip_address}"
        )

        return True


    async def get_blocked_ips(self):
        async with AsyncSessionLocal() as db:
            result = await db.execute(
                select(BlockedIp)
                .where(
                    BlockedIp.is_active.is_(True)
                )
                .order_by(
                    BlockedIp.blocked_at.desc()
                )
            )

            records = result.scalars().all()

            return [
                {
                    "ip_address": item.ip_address,
                    "client_key": item.client_key,
                    "reason": item.reason,
                    "violation_count": item.violation_count,
                    "total_risk": item.total_risk,
                    "blocked_at": (
                        item.blocked_at.strftime(
                            "%d/%m/%Y %H:%M:%S"
                        )
                        if item.blocked_at
                        else ""
                    ),
                    "expires_at": (
                        item.expires_at.strftime(
                            "%d/%m/%Y %H:%M:%S"
                        )
                        if item.expires_at
                        else None
                    )
                }
                for item in records
            ]


ip_blocker = IPBlocker()