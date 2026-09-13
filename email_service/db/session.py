"""
Database engine and async session factory for AutoMail AI SaaS.
Supports PostgreSQL (asyncpg) in staging/production, and SQLite (aiosqlite)
for zero-friction local developer testing and CI test suites.
"""

import os
from typing import AsyncGenerator
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from .models import Base

# Database Connection URL
# Production: postgresql+asyncpg://user:pass@host:5432/automail
# Development/Test: sqlite+aiosqlite:///./email_service/data/automail_dev.db
DEFAULT_DB_URL = "sqlite+aiosqlite:///./email_service/data/automail_dev.db"
DATABASE_URL = os.getenv("DATABASE_URL", DEFAULT_DB_URL)

# Normalize postgres:// to postgresql+asyncpg:// if provided by cloud platforms (e.g. Render/Heroku)
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql+asyncpg://", 1)
elif DATABASE_URL.startswith("postgresql://") and "+asyncpg" not in DATABASE_URL:
    DATABASE_URL = DATABASE_URL.replace("postgresql://", "postgresql+asyncpg://", 1)

# Engine configuration
# Note: PgBouncer transaction pooling & connection pool tuning (size/max_overflow)
# is cataloged as a Phase 2 concern.
engine_kwargs = {"echo": False}
if "sqlite" in DATABASE_URL:
    engine_kwargs["connect_args"] = {"check_same_thread": False}
else:
    engine_kwargs["pool_size"] = int(os.getenv("DB_POOL_SIZE", "10"))
    engine_kwargs["max_overflow"] = int(os.getenv("DB_MAX_OVERFLOW", "20"))
    engine_kwargs["pool_recycle"] = 3600
    engine_kwargs["pool_pre_ping"] = True

async_engine = create_async_engine(DATABASE_URL, **engine_kwargs)

# Async Session Factory
AsyncSessionLocal = async_sessionmaker(
    bind=async_engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False
)


async def get_db_session() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency for yielding async database sessions."""
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


async def init_db():
    """Create tables if they do not exist."""
    async with async_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
