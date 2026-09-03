from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine
)
from sqlalchemy.orm import DeclarativeBase

from app.core.config import settings

def get_async_database_url(url: str) -> str:
    if url.startswith("postgresql+asyncpg://"):
        return url

    if url.startswith("postgresql://"):
        return url.replace(
            "postgresql://",
            "postgresql+asyncpg://",
            1
        )

    return url

DATABASE_URL = get_async_database_url(
    settings.DATABASE_URL
)

engine = create_async_engine(
    DATABASE_URL,
    pool_pre_ping=True
)

AsyncSessionLocal = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False
)

class Base(DeclarativeBase):
    pass