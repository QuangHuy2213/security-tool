from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase

from app.core.config import settings


def normalize_database_url(url: str) -> str:
    if not url:
        raise RuntimeError(
            "DATABASE_URL chưa được cấu hình."
        )

    url = url.strip()

    # Nếu vô tình copy cả dấu nháy vào Render
    if (
        (url.startswith('"') and url.endswith('"'))
        or
        (url.startswith("'") and url.endswith("'"))
    ):
        url = url[1:-1].strip()

    # Không dùng tham số này với asyncpg
    url = url.replace(
        "?pgbouncer=true",
        ""
    )

    url = url.replace(
        "&pgbouncer=true",
        ""
    )

    if url.startswith(
        "postgresql+asyncpg://"
    ):
        return url

    if url.startswith(
        "postgresql://"
    ):
        return url.replace(
            "postgresql://",
            "postgresql+asyncpg://",
            1,
        )

    if url.startswith(
        "postgres://"
    ):
        return url.replace(
            "postgres://",
            "postgresql+asyncpg://",
            1,
        )

    raise RuntimeError(
        "DATABASE_URL không đúng định dạng PostgreSQL."
    )


DATABASE_URL = normalize_database_url(
    settings.DATABASE_URL
)

engine = create_async_engine(
    DATABASE_URL,
    pool_pre_ping=True,
)

AsyncSessionLocal = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


class Base(DeclarativeBase):
    pass