from datetime import datetime, timedelta

from sqlalchemy import select

from app.core.config import settings
from app.database.database import AsyncSessionLocal
from app.database.models import SecurityRateLimit


class RateLimiter:

    async def check(
        self,
        client_key: str,
        endpoint: str
    ):
        now = datetime.now()

        window_seconds = (
            settings.RATE_LIMIT_WINDOW_SECONDS
        )

        max_requests = (
            settings.RATE_LIMIT_REQUESTS
        )

        async with AsyncSessionLocal() as db:
            result = await db.execute(
                select(SecurityRateLimit)
                .where(
                    SecurityRateLimit.client_key
                    == client_key,

                    SecurityRateLimit.endpoint
                    == endpoint
                )
                .with_for_update()
            )

            record = result.scalar_one_or_none()

            if record is None:
                record = SecurityRateLimit(
                    client_key=client_key,
                    endpoint=endpoint,
                    request_count=1,
                    window_start=now,
                    updated_at=now
                )

                db.add(record)

                await db.commit()

                return {
                    "allowed": True,
                    "count": 1,
                    "limit": max_requests
                }

            window_end = (
                record.window_start
                + timedelta(
                    seconds=window_seconds
                )
            )

            # Hết window cũ -> reset
            if now >= window_end:
                record.request_count = 1
                record.window_start = now
                record.updated_at = now

                await db.commit()

                return {
                    "allowed": True,
                    "count": 1,
                    "limit": max_requests
                }

            # Window hiện tại
            record.request_count += 1
            record.updated_at = now

            count = record.request_count

            await db.commit()

            remaining_seconds = max(
                0,
                int(
                    (
                        window_end - now
                    ).total_seconds()
                )
            )

            return {
                "allowed": (
                    count <= max_requests
                ),
                "count": count,
                "limit": max_requests,
                "retry_after": (
                    remaining_seconds
                )
            }


rate_limiter = RateLimiter()