import hashlib
from datetime import datetime, timedelta

from sqlalchemy import select

from app.core.config import settings
from app.database.database import AsyncSessionLocal
from app.database.models import SecurityLoginAttempt


def hash_identifier(identifier: str):
    """
    Hash email/username để không lưu trực tiếp identifier vào bảng security.
    """
    normalized = identifier.strip().lower()

    return hashlib.sha256(
        normalized.encode("utf-8")
    ).hexdigest()


class BruteForceDetector:
    async def check_blocked(
        self,
        client_key: str,
        identifier: str,
        endpoint: str
    ):
        identifier_hash = hash_identifier(
            identifier
        )

        async with AsyncSessionLocal() as db:
            result = await db.execute(
                select(SecurityLoginAttempt).where(
                    SecurityLoginAttempt.client_key == client_key,
                    SecurityLoginAttempt.identifier_hash == identifier_hash,
                    SecurityLoginAttempt.endpoint == endpoint
                )
            )

            attempt = result.scalar_one_or_none()

            if attempt is None:
                return {
                    "blocked": False
                }

            now = datetime.now()

            if (
                attempt.blocked_until is not None
                and attempt.blocked_until > now
            ):
                remaining = int(
                    (
                        attempt.blocked_until - now
                    ).total_seconds()
                )

                return {
                    "blocked": True,
                    "retry_after": remaining
                }

            return {
                "blocked": False
            }


    async def register_failure(
        self,
        client_key: str,
        identifier: str,
        endpoint: str
    ):
        identifier_hash = hash_identifier(
            identifier
        )

        now = datetime.now()

        async with AsyncSessionLocal() as db:
            result = await db.execute(
                select(SecurityLoginAttempt)
                .where(
                    SecurityLoginAttempt.client_key == client_key,
                    SecurityLoginAttempt.identifier_hash == identifier_hash,
                    SecurityLoginAttempt.endpoint == endpoint
                )
                .with_for_update()
            )

            attempt = result.scalar_one_or_none()

            if attempt is None:
                attempt = SecurityLoginAttempt(
                    client_key=client_key,
                    identifier_hash=identifier_hash,
                    endpoint=endpoint,
                    failed_count=1,
                    window_start=now,
                    blocked_until=None,
                    updated_at=now
                )

                db.add(attempt)

                await db.commit()

                return {
                    "failed_count": 1,
                    "blocked": False
                }

            window_end = (
                attempt.window_start
                + timedelta(
                    seconds=settings.BRUTE_FORCE_WINDOW_SECONDS
                )
            )

            if now >= window_end:
                attempt.failed_count = 1
                attempt.window_start = now
                attempt.blocked_until = None
                attempt.updated_at = now

                await db.commit()

                return {
                    "failed_count": 1,
                    "blocked": False
                }

            attempt.failed_count += 1
            attempt.updated_at = now

            should_block = (
                attempt.failed_count
                >= settings.BRUTE_FORCE_MAX_FAILURES
            )

            if should_block:
                attempt.blocked_until = (
                    now
                    + timedelta(
                        seconds=settings.BRUTE_FORCE_BLOCK_SECONDS
                    )
                )

            failed_count = attempt.failed_count
            blocked_until = attempt.blocked_until

            await db.commit()

            retry_after = 0

            if blocked_until:
                retry_after = int(
                    (
                        blocked_until - now
                    ).total_seconds()
                )

            return {
                "failed_count": failed_count,
                "blocked": should_block,
                "retry_after": retry_after
            }


    async def reset_success(
        self,
        client_key: str,
        identifier: str,
        endpoint: str
    ):
        identifier_hash = hash_identifier(
            identifier
        )

        async with AsyncSessionLocal() as db:
            result = await db.execute(
                select(SecurityLoginAttempt).where(
                    SecurityLoginAttempt.client_key == client_key,
                    SecurityLoginAttempt.identifier_hash == identifier_hash,
                    SecurityLoginAttempt.endpoint == endpoint
                )
            )

            attempt = result.scalar_one_or_none()

            if attempt is None:
                return

            attempt.failed_count = 0
            attempt.blocked_until = None
            attempt.window_start = datetime.now()
            attempt.updated_at = datetime.now()

            await db.commit()


brute_force_detector = BruteForceDetector()