import hashlib

from sqlalchemy import text


def advisory_lock_id(namespace: str, *parts: str) -> int:
    """Build a stable signed bigint key for PostgreSQL advisory locks."""
    value = "\x1f".join((namespace, *parts))
    raw = hashlib.sha256(value.encode("utf-8")).digest()[:8]
    return int.from_bytes(raw, byteorder="big", signed=True)


async def acquire_advisory_lock(db, namespace: str, *parts: str) -> None:
    await db.execute(
        text("SELECT pg_advisory_xact_lock(:lock_id)"),
        {"lock_id": advisory_lock_id(namespace, *parts)},
    )
