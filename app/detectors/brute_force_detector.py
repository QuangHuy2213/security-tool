import hashlib

from datetime import (
    datetime,
    timedelta,
)

from sqlalchemy import select

from app.core.config import settings
from app.database.database import AsyncSessionLocal
from app.database.locking import (
    acquire_advisory_lock,
)
from app.database.models import (
    SecurityLoginAttempt,
)


# =========================================================
# HASH IDENTIFIER
# =========================================================

def hash_identifier(
    identifier: str
):
    return hashlib.sha256(
        identifier
        .strip()
        .lower()
        .encode("utf-8")
    ).hexdigest()


# =========================================================
# HELPER
# =========================================================

def get_retry_after(
    blocked_until,
    now: datetime,
):
    if (
        not blocked_until
        or blocked_until <= now
    ):
        return 0

    return max(
        1,
        int(
            (
                blocked_until
                - now
            ).total_seconds()
        )
        + 1,
    )


class BruteForceDetector:

    # =====================================================
    # CHECK BLOCK
    # =====================================================

    async def check_blocked(
        self,
        client_key: str,
        identifier: str,
        endpoint: str,
    ):
        identifier_hash = (
            hash_identifier(
                identifier
            )
        )

        now = datetime.now()

        async with AsyncSessionLocal() as db:

            result = await db.execute(
                select(
                    SecurityLoginAttempt
                ).where(
                    SecurityLoginAttempt
                    .client_key
                    == client_key,

                    SecurityLoginAttempt
                    .identifier_hash
                    == identifier_hash,

                    SecurityLoginAttempt
                    .endpoint
                    == endpoint,
                )
            )

            attempt = (
                result
                .scalars()
                .first()
            )

            if attempt is None:
                return {
                    "blocked": False,
                    "newly_blocked": False,
                    "retry_after": 0,
                }

            currently_blocked = bool(
                attempt.blocked_until
                and
                attempt.blocked_until
                > now
            )

            if currently_blocked:
                return {
                    "blocked": True,
                    "newly_blocked": False,
                    "retry_after": (
                        get_retry_after(
                            attempt.blocked_until,
                            now,
                        )
                    ),
                }

            return {
                "blocked": False,
                "newly_blocked": False,
                "retry_after": 0,
            }


    # =====================================================
    # REGISTER FAILURE
    # =====================================================

    async def register_failure(
        self,
        client_key: str,
        identifier: str,
        endpoint: str,
    ):
        identifier_hash = (
            hash_identifier(
                identifier
            )
        )

        now = datetime.now()

        async with AsyncSessionLocal() as db:

            async with db.begin():

                # -----------------------------------------
                # LOCK
                # -----------------------------------------

                await acquire_advisory_lock(
                    db,
                    "brute-force",
                    client_key,
                    identifier_hash,
                    endpoint,
                )

                # -----------------------------------------
                # READ CURRENT STATE
                # -----------------------------------------

                result = await db.execute(
                    select(
                        SecurityLoginAttempt
                    ).where(
                        SecurityLoginAttempt
                        .client_key
                        == client_key,

                        SecurityLoginAttempt
                        .identifier_hash
                        == identifier_hash,

                        SecurityLoginAttempt
                        .endpoint
                        == endpoint,
                    )
                )

                attempt = (
                    result
                    .scalars()
                    .first()
                )


                # =========================================
                # CHƯA CÓ RECORD
                # =========================================

                if attempt is None:

                    attempt = (
                        SecurityLoginAttempt(
                            client_key=client_key,
                            identifier_hash=(
                                identifier_hash
                            ),
                            endpoint=endpoint,
                            failed_count=1,
                            window_start=now,
                            blocked_until=None,
                            updated_at=now,
                        )
                    )

                    db.add(
                        attempt
                    )

                    return {
                        "failed_count": 1,
                        "blocked": False,
                        "newly_blocked": False,
                        "retry_after": 0,
                    }


                # =========================================
                # ĐÃ BỊ BLOCK BỞI REQUEST KHÁC
                #
                # Quan trọng cho concurrent requests:
                #
                # Request A:
                # failure #5 -> block
                #
                # Request B đã vượt check_blocked trước đó
                # nhưng khi vào lock sẽ thấy blocked_until.
                #
                # Không được trả 401 cho request B.
                # =========================================

                if (
                    attempt.blocked_until
                    and
                    attempt.blocked_until > now
                ):

                    return {
                        "failed_count": (
                            attempt.failed_count
                        ),
                        "blocked": True,
                        "newly_blocked": False,
                        "retry_after": (
                            get_retry_after(
                                attempt.blocked_until,
                                now,
                            )
                        ),
                    }


                # =========================================
                # CHECK WINDOW
                # =========================================

                window_end = (
                    attempt.window_start
                    +
                    timedelta(
                        seconds=(
                            settings
                            .BRUTE_FORCE_WINDOW_SECONDS
                        )
                    )
                )


                # =========================================
                # WINDOW ĐÃ HẾT
                #
                # Bắt đầu lại từ lần sai đầu tiên.
                # =========================================

                if now >= window_end:

                    attempt.failed_count = 1

                    attempt.window_start = (
                        now
                    )

                    attempt.blocked_until = (
                        None
                    )

                    attempt.updated_at = (
                        now
                    )

                    return {
                        "failed_count": 1,
                        "blocked": False,
                        "newly_blocked": False,
                        "retry_after": 0,
                    }


                # =========================================
                # TĂNG FAILURE
                # =========================================

                attempt.failed_count += 1

                attempt.updated_at = now

                newly_blocked = False


                # =========================================
                # ĐẠT NGƯỠNG BRUTE FORCE
                # =========================================

                if (
                    attempt.failed_count
                    >=
                    settings
                    .BRUTE_FORCE_MAX_FAILURES
                ):

                    # Chỉ tạo block mới nếu hiện chưa block.
                    if (
                        not attempt.blocked_until
                        or
                        attempt.blocked_until
                        <= now
                    ):

                        attempt.blocked_until = (
                            now
                            +
                            timedelta(
                                seconds=(
                                    settings
                                    .BRUTE_FORCE_BLOCK_SECONDS
                                )
                            )
                        )

                        newly_blocked = True


                # =========================================
                # TRẠNG THÁI BLOCK HIỆN TẠI
                # =========================================

                currently_blocked = bool(
                    attempt.blocked_until
                    and
                    attempt.blocked_until
                    > now
                )


                retry_after = (
                    get_retry_after(
                        attempt.blocked_until,
                        now,
                    )
                )


                return {
                    "failed_count": (
                        attempt.failed_count
                    ),

                    # Login hiện có đang bị khóa không
                    "blocked": (
                        currently_blocked
                    ),

                    # Chỉ True đúng request kích hoạt khóa
                    "newly_blocked": (
                        newly_blocked
                    ),

                    "retry_after": (
                        retry_after
                    ),
                }


    # =====================================================
    # LOGIN SUCCESS
    # =====================================================

    async def reset_success(
        self,
        client_key: str,
        identifier: str,
        endpoint: str,
    ):
        identifier_hash = (
            hash_identifier(
                identifier
            )
        )

        async with AsyncSessionLocal() as db:

            async with db.begin():

                await acquire_advisory_lock(
                    db,
                    "brute-force",
                    client_key,
                    identifier_hash,
                    endpoint,
                )

                result = await db.execute(
                    select(
                        SecurityLoginAttempt
                    ).where(
                        SecurityLoginAttempt
                        .client_key
                        == client_key,

                        SecurityLoginAttempt
                        .identifier_hash
                        == identifier_hash,

                        SecurityLoginAttempt
                        .endpoint
                        == endpoint,
                    )
                )

                attempt = (
                    result
                    .scalars()
                    .first()
                )

                if attempt:

                    now = datetime.now()

                    attempt.failed_count = 0

                    attempt.blocked_until = (
                        None
                    )

                    attempt.window_start = (
                        now
                    )

                    attempt.updated_at = (
                        now
                    )


brute_force_detector = (
    BruteForceDetector()
)