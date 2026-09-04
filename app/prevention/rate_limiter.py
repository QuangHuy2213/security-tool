from datetime import datetime, timedelta

from sqlalchemy import select

from app.core.config import settings
from app.database.database import AsyncSessionLocal
from app.database.locking import acquire_advisory_lock
from app.database.models import SecurityRateLimit


ABUSE_COUNTER_ENDPOINT = "__api_abuse_strikes__"


def get_rate_limit_group(method: str, path: str) -> tuple[str, int]:
    normalized = path.lower().rstrip("/") or "/"
    if any(part in normalized for part in ("/payment", "/checkout")):
        return "payment", settings.RATE_LIMIT_PAYMENT_REQUESTS
    if any(part in normalized for part in ("/upload", "/media", "/files")):
        return "upload", settings.RATE_LIMIT_UPLOAD_REQUESTS
    if method.upper() == "GET":
        return "read", settings.RATE_LIMIT_READ_REQUESTS
    if method.upper() in {"POST", "PUT", "PATCH", "DELETE"}:
        return "write", settings.RATE_LIMIT_WRITE_REQUESTS
    return "default", settings.RATE_LIMIT_REQUESTS


class RateLimiter:
    async def check(self, client_key: str, endpoint: str, method: str = "GET"):
        now = datetime.now()
        window_seconds = settings.RATE_LIMIT_WINDOW_SECONDS
        group, max_requests = get_rate_limit_group(method, endpoint)
        bucket = f"group:{group}"

        async with AsyncSessionLocal() as db:
            async with db.begin():
                await acquire_advisory_lock(db, "rate-limit", client_key, bucket)
                result = await db.execute(
                    select(SecurityRateLimit).where(
                        SecurityRateLimit.client_key == client_key,
                        SecurityRateLimit.endpoint == bucket,
                    )
                )
                record = result.scalars().first()
                if record is None:
                    db.add(SecurityRateLimit(
                        client_key=client_key, endpoint=bucket, request_count=1,
                        window_start=now, updated_at=now,
                    ))
                    return self._result(True, 1, max_requests, group, window_seconds, False)

                window_end = record.window_start + timedelta(seconds=window_seconds)
                if now >= window_end:
                    record.request_count = 1
                    record.window_start = now
                    record.updated_at = now
                    return self._result(True, 1, max_requests, group, window_seconds, False)

                record.request_count += 1
                record.updated_at = now
                count = record.request_count
                retry_after = max(1, int((window_end - now).total_seconds()) + 1)
                return self._result(
                    count <= max_requests, count, max_requests, group,
                    retry_after, count == max_requests + 1,
                )

    async def register_abuse_strike(self, client_key: str):
        now = datetime.now()
        window_seconds = settings.API_ABUSE_STRIKE_WINDOW_SECONDS
        async with AsyncSessionLocal() as db:
            async with db.begin():
                await acquire_advisory_lock(db, "api-abuse", client_key)
                result = await db.execute(
                    select(SecurityRateLimit).where(
                        SecurityRateLimit.client_key == client_key,
                        SecurityRateLimit.endpoint == ABUSE_COUNTER_ENDPOINT,
                    )
                )
                record = result.scalars().first()
                if record is None:
                    record = SecurityRateLimit(
                        client_key=client_key, endpoint=ABUSE_COUNTER_ENDPOINT,
                        request_count=1, window_start=now, updated_at=now,
                    )
                    db.add(record)
                    strikes = 1
                elif now >= record.window_start + timedelta(seconds=window_seconds):
                    record.request_count = 1
                    record.window_start = now
                    record.updated_at = now
                    strikes = 1
                else:
                    record.request_count += 1
                    record.updated_at = now
                    strikes = record.request_count

                return {
                    "strikes": strikes,
                    "max_strikes": settings.API_ABUSE_MAX_STRIKES,
                    "escalated": strikes == settings.API_ABUSE_MAX_STRIKES,
                }

    @staticmethod
    def _result(allowed, count, limit, group, retry_after, new_burst):
        return {
            "allowed": allowed, "count": count, "limit": limit,
            "group": group, "retry_after": retry_after, "new_burst": new_burst,
        }


rate_limiter = RateLimiter()
