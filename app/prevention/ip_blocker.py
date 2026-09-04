from datetime import (
    datetime,
    timedelta,
)

from sqlalchemy import (
    select,
    or_,
    delete,
)

from app.core.config import (
    settings,
)

from app.database.database import (
    AsyncSessionLocal,
)

from app.database.locking import (
    acquire_advisory_lock,
)

from app.database.models import (
    ClientViolation,
    BlockedIp,
    SecurityRateLimit,
)


# =========================================================
# RATE LIMIT BUCKETS
# =========================================================

RATE_LIMIT_BUCKETS = (
    "group:default",
    "group:read",
    "group:write",
    "group:payment",
    "group:upload",
)


# =========================================================
# HELPER - NORMALIZE ATTACK TYPE
# =========================================================

def normalize_attack_type(
    attack_type: str,
):
    attack_map = {
        "Cross-Site Scripting (XSS)":
            "XSS",

        "SQL Injection":
            "SQL_INJECTION",

        "Brute Force":
            "BRUTE_FORCE",

        "API Abuse":
            "API_ABUSE",

        "Unauthorized Access":
            "UNAUTHORIZED_ACCESS",

        "Nhiều dấu hiệu tấn công":
            "SUSPICIOUS_REQUEST",
    }

    return attack_map.get(
        attack_type,
        "SUSPICIOUS_REQUEST",
    )


# =========================================================
# HELPER - FORMAT DATETIME
# =========================================================

def format_datetime(
    value,
):
    if not value:
        return None

    return value.strftime(
        "%d/%m/%Y %H:%M:%S"
    )


# =========================================================
# HELPER - REMAINING SECONDS
# =========================================================

def remaining_seconds(
    expires_at,
):
    if not expires_at:
        return None

    seconds = int(
        (
            expires_at
            - datetime.now()
        ).total_seconds()
    )

    return max(
        seconds,
        0,
    )


# =========================================================
# HELPER - REMAINING TEXT
# =========================================================

def remaining_text(
    seconds,
):
    if seconds is None:
        return "Không giới hạn"

    if seconds <= 0:
        return "Đã hết hạn"

    hours = (
        seconds
        // 3600
    )

    minutes = (
        seconds
        % 3600
    ) // 60

    secs = (
        seconds
        % 60
    )

    if hours:

        return (
            f"{hours} giờ "
            f"{minutes} phút"
        )

    if minutes:

        return (
            f"{minutes} phút "
            f"{secs} giây"
        )

    return (
        f"{secs} giây"
    )


# =========================================================
# IP / CLIENT BLOCKER
# =========================================================

class IPBlocker:

    # =====================================================
    # REGISTER VIOLATION
    # =====================================================

    async def register_violation(
        self,
        ip_address: str,
        client_key: str,
        risk_score: int,
        attack_type: str,
    ):
        now = datetime.now()

        normalized_attack_type = (
            normalize_attack_type(
                attack_type
            )
        )

        async with AsyncSessionLocal() as db:

            # ---------------------------------------------
            # Lock theo client để tránh request concurrent
            # cùng tăng violation sai.
            # ---------------------------------------------

            await acquire_advisory_lock(
                db,
                "client-violation",
                client_key,
            )

            result = await db.execute(
                select(
                    ClientViolation
                ).where(
                    ClientViolation
                    .client_key
                    == client_key
                )
            )

            violation = (
                result
                .scalar_one_or_none()
            )

            # =============================================
            # CHƯA CÓ CLIENT
            # =============================================

            if violation is None:

                violation = (
                    ClientViolation(
                        client_key=(
                            client_key
                        ),

                        ip_address=(
                            ip_address
                        ),

                        violation_count=1,

                        total_risk=(
                            risk_score
                        ),

                        last_attack_type=(
                            normalized_attack_type
                        ),

                        first_violation_at=(
                            now
                        ),

                        last_violation_at=(
                            now
                        ),
                    )
                )

                db.add(
                    violation
                )

            # =============================================
            # CLIENT ĐÃ CÓ
            # =============================================

            else:

                violation.ip_address = (
                    ip_address
                )

                violation.violation_count += (
                    1
                )

                violation.total_risk += (
                    risk_score
                )

                violation.last_attack_type = (
                    normalized_attack_type
                )

                violation.last_violation_at = (
                    now
                )

            await db.commit()

            await db.refresh(
                violation
            )

            count = (
                violation
                .violation_count
            )

            total_risk = (
                violation
                .total_risk
            )

        print(
            f"[VI PHẠM] "
            f"IP={ip_address} "
            f"| Client="
            f"{client_key[:12]} "
            f"| Lần={count} "
            f"| Risk={risk_score} "
            f"| Attack="
            f"{normalized_attack_type}"
        )


        # =================================================
        # AUTO GLOBAL BLOCK
        # =================================================

        should_block = (
            risk_score
            >=
            settings
            .IMMEDIATE_BLOCK_SCORE

            or

            count
            >=
            settings
            .MAX_VIOLATIONS
        )

        if should_block:

            reason = (
                f"Phát hiện "
                f"{attack_type}. "
                f"Số lần vi phạm: "
                f"{count}. "
                f"Risk Score gần nhất: "
                f"{risk_score}/100."
            )

            await self.block_ip(
                ip_address=(
                    ip_address
                ),

                client_key=(
                    client_key
                ),

                reason=reason,

                violation_count=(
                    count
                ),

                total_risk=(
                    total_risk
                ),
            )


        blocked_info = (
            await self.is_blocked(
                ip_address=ip_address,
                client_key=client_key,
            )
        )

        return {
            "violation_count":
                count,

            "total_risk":
                total_risk,

            "blocked":
                blocked_info
                is not None,
        }


    # =====================================================
    # GLOBAL BLOCK CLIENT
    # =====================================================

    async def block_ip(
        self,
        ip_address: str,
        client_key: str,
        reason: str,
        violation_count: int,
        total_risk: int,
    ):
        """
        Tên hàm giữ lại để tương thích code hiện tại.

        Với client_key khác None,
        đây thực tế là CLIENT-SCOPED BLOCK.

        IP không được dùng để block các client khác
        cùng NAT.
        """

        now = datetime.now()

        expires_at = (
            now
            +
            timedelta(
                seconds=(
                    settings
                    .BLOCK_DURATION_SECONDS
                )
            )
        )

        async with AsyncSessionLocal() as db:

            await acquire_advisory_lock(
                db,
                "client-block",
                client_key,
            )

            result = await db.execute(
                select(
                    BlockedIp
                ).where(
                    BlockedIp
                    .client_key
                    == client_key,

                    BlockedIp
                    .is_active
                    .is_(True),
                )
            )

            blocked = (
                result
                .scalars()
                .first()
            )

            # =============================================
            # CHƯA CÓ BLOCK RECORD
            # =============================================

            if blocked is None:

                blocked = (
                    BlockedIp(
                        ip_address=(
                            ip_address
                        ),

                        client_key=(
                            client_key
                        ),

                        reason=(
                            reason
                        ),

                        violation_count=(
                            violation_count
                        ),

                        total_risk=(
                            total_risk
                        ),

                        is_active=True,

                        blocked_at=(
                            now
                        ),

                        expires_at=(
                            expires_at
                        ),
                    )
                )

                db.add(
                    blocked
                )

            # =============================================
            # ĐÃ CÓ BLOCK RECORD
            # =============================================

            else:

                blocked.ip_address = (
                    ip_address
                )

                blocked.reason = (
                    reason
                )

                blocked.violation_count = (
                    violation_count
                )

                blocked.total_risk = (
                    total_risk
                )

                blocked.is_active = (
                    True
                )

                blocked.blocked_at = (
                    now
                )

                blocked.expires_at = (
                    expires_at
                )

            await db.commit()

        print(
            f"[KHÓA CLIENT] "
            f"IP={ip_address} "
            f"| Client="
            f"{client_key[:12]} "
            f"| Hết hạn="
            f"{expires_at}"
        )


    # =====================================================
    # CLEANUP EXPIRED BLOCK
    # =====================================================

    async def cleanup_expired_blocks(
        self,
    ):
        now = datetime.now()

        async with AsyncSessionLocal() as db:

            result = await db.execute(
                select(
                    BlockedIp
                ).where(
                    BlockedIp
                    .is_active
                    .is_(True),

                    BlockedIp
                    .expires_at
                    .is_not(None),

                    BlockedIp
                    .expires_at
                    <= now,
                )
            )

            expired = (
                result
                .scalars()
                .all()
            )

            if not expired:
                return 0

            for item in expired:

                item.is_active = (
                    False
                )

            await db.commit()

            return len(
                expired
            )


    # =====================================================
    # CHECK GLOBAL BLOCK
    # =====================================================

    async def is_blocked(
        self,
        ip_address: str,
        client_key: str,
    ):
        await (
            self
            .cleanup_expired_blocks()
        )

        now = datetime.now()

        async with AsyncSessionLocal() as db:

            result = await db.execute(
                select(
                    BlockedIp
                ).where(
                    # -------------------------------------
                    # Block phải active.
                    # -------------------------------------

                    BlockedIp
                    .is_active
                    .is_(True),

                    # -------------------------------------
                    # CLIENT BLOCK:
                    #
                    # client_key phải match.
                    #
                    # IP BLOCK:
                    #
                    # Chỉ match IP nếu block record
                    # không có client_key.
                    #
                    # Tránh một user sau NAT khiến
                    # cả mạng bị block.
                    # -------------------------------------

                    or_(
                        BlockedIp
                        .client_key
                        == client_key,

                        (
                            BlockedIp
                            .client_key
                            .is_(None)

                            &

                            (
                                BlockedIp
                                .ip_address
                                == ip_address
                            )
                        ),
                    ),

                    # -------------------------------------
                    # Chưa hết hạn.
                    # -------------------------------------

                    or_(
                        BlockedIp
                        .expires_at
                        .is_(None),

                        BlockedIp
                        .expires_at
                        > now,
                    ),
                )
                .order_by(
                    BlockedIp
                    .blocked_at
                    .desc()
                )
            )

            blocked = (
                result
                .scalars()
                .first()
            )

            if blocked is None:
                return None

            seconds = (
                remaining_seconds(
                    blocked
                    .expires_at
                )
            )

            return {
                "blocked":
                    True,

                "ip_address":
                    blocked
                    .ip_address,

                "client_key":
                    blocked
                    .client_key,

                "reason":
                    blocked
                    .reason,

                "violation_count":
                    blocked
                    .violation_count,

                "total_risk":
                    blocked
                    .total_risk,

                "blocked_at":
                    format_datetime(
                        blocked
                        .blocked_at
                    ),

                "expires_at":
                    format_datetime(
                        blocked
                        .expires_at
                    ),

                "remaining_seconds":
                    seconds,

                "remaining_text":
                    remaining_text(
                        seconds
                    ),
            }


    # =====================================================
    # RESET CLIENT SECURITY STATE
    # =====================================================

    async def _reset_violation(
        self,
        db,
        client_key: str,
    ):
        """
        Admin chủ động bỏ chặn client.

        Reset:
        - ClientViolation
        - API Abuse strikes
        - read bucket
        - write bucket
        - payment bucket
        - upload bucket
        - default bucket

        Không reset Brute Force login state vì đây là
        cơ chế khóa đăng nhập độc lập.
        """

        # -------------------------------------------------
        # Lock ClientViolation trước khi reset.
        # -------------------------------------------------

        await acquire_advisory_lock(
            db,
            "client-violation",
            client_key,
        )

        # -------------------------------------------------
        # Lock API Abuse counter.
        # -------------------------------------------------

        await acquire_advisory_lock(
            db,
            "api-abuse",
            client_key,
        )

        # -------------------------------------------------
        # Lock tất cả Rate Limit bucket theo đúng namespace
        # mà RateLimiter đang sử dụng.
        # -------------------------------------------------

        for bucket in RATE_LIMIT_BUCKETS:

            await acquire_advisory_lock(
                db,
                "rate-limit",
                client_key,
                bucket,
            )

        # -------------------------------------------------
        # RESET CLIENT VIOLATION
        # -------------------------------------------------

        result = await db.execute(
            select(
                ClientViolation
            ).where(
                ClientViolation
                .client_key
                == client_key
            )
        )

        violation = (
            result
            .scalar_one_or_none()
        )

        if violation:

            violation.violation_count = (
                0
            )

            violation.total_risk = (
                0
            )

            violation.last_attack_type = (
                None
            )

            violation.last_violation_at = (
                datetime.now()
            )

        # -------------------------------------------------
        # RESET TOÀN BỘ RATE LIMIT / API ABUSE STATE
        # -------------------------------------------------

        await db.execute(
            delete(
                SecurityRateLimit
            ).where(
                SecurityRateLimit
                .client_key
                == client_key
            )
        )


    # =====================================================
    # UNBLOCK BY IP
    # =====================================================

    async def unblock_ip(
        self,
        ip_address: str,
    ):
        async with AsyncSessionLocal() as db:

            result = await db.execute(
                select(
                    BlockedIp
                ).where(
                    BlockedIp
                    .ip_address
                    == ip_address,

                    BlockedIp
                    .is_active
                    .is_(True),
                )
            )

            records = (
                result
                .scalars()
                .all()
            )

            if not records:
                return False

            client_keys = set()

            for record in records:

                record.is_active = (
                    False
                )

                if record.client_key:

                    client_keys.add(
                        record.client_key
                    )

            # Reset state của các client được unblock.
            for client_key in sorted(
                client_keys
            ):

                await (
                    self
                    ._reset_violation(
                        db,
                        client_key,
                    )
                )

            await db.commit()

        print(
            f"[BỎ CHẶN IP] "
            f"{ip_address}"
        )

        return True


    # =====================================================
    # UNBLOCK BY CLIENT
    # =====================================================

    async def unblock_client(
        self,
        client_key: str,
    ):
        async with AsyncSessionLocal() as db:

            # -------------------------------------------------
            # Đồng bộ với block_ip() để tránh admin unblock
            # đúng lúc request khác đang tạo block.
            # -------------------------------------------------

            await acquire_advisory_lock(
                db,
                "client-block",
                client_key,
            )

            result = await db.execute(
                select(
                    BlockedIp
                ).where(
                    BlockedIp
                    .client_key
                    == client_key,

                    BlockedIp
                    .is_active
                    .is_(True),
                )
            )

            records = (
                result
                .scalars()
                .all()
            )

            if not records:
                return False

            # Disable toàn bộ block record active
            # của client.
            for record in records:

                record.is_active = (
                    False
                )

            # Reset:
            #
            # ClientViolation
            # Rate Limit bucket
            # API Abuse strikes
            await self._reset_violation(
                db,
                client_key,
            )

            await db.commit()

        print(
            "[BỎ CHẶN CLIENT] "
            f"{client_key[:12]}"
        )

        return True


    # =====================================================
    # GET BLOCKED CLIENT / IP LIST
    # =====================================================

    async def get_blocked_ips(
        self,
    ):
        await (
            self
            .cleanup_expired_blocks()
        )

        now = datetime.now()

        async with AsyncSessionLocal() as db:

            result = await db.execute(
                select(
                    BlockedIp
                )
                .where(
                    BlockedIp
                    .is_active
                    .is_(True),

                    or_(
                        BlockedIp
                        .expires_at
                        .is_(None),

                        BlockedIp
                        .expires_at
                        > now,
                    ),
                )
                .order_by(
                    BlockedIp
                    .blocked_at
                    .desc()
                )
            )

            records = (
                result
                .scalars()
                .all()
            )

            response = []

            for item in records:

                seconds = (
                    remaining_seconds(
                        item
                        .expires_at
                    )
                )

                response.append({
                    "id": getattr(
                        item,
                        "id",
                        None,
                    ),

                    "ip_address":
                        item
                        .ip_address,

                    "client_key":
                        item
                        .client_key,

                    "client_key_short": (
                        (
                            item
                            .client_key[:12]
                            + "..."
                        )

                        if item.client_key

                        else "-"
                    ),

                    "reason":
                        item
                        .reason,

                    "violation_count":
                        item
                        .violation_count,

                    "total_risk":
                        item
                        .total_risk,

                    "is_active":
                        item
                        .is_active,

                    "status":
                        "Đang chặn",

                    "blocked_at":
                        format_datetime(
                            item
                            .blocked_at
                        ),

                    "expires_at":
                        format_datetime(
                            item
                            .expires_at
                        ),

                    "remaining_seconds":
                        seconds,

                    "remaining_text":
                        remaining_text(
                            seconds
                        ),
                })

            return response


# =========================================================
# INSTANCE
# =========================================================

ip_blocker = IPBlocker()