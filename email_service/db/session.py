"""
Database engine and async session factory for AutoMail AI SaaS.
Supports PostgreSQL (asyncpg) in staging/production, and SQLite (aiosqlite)
for zero-friction local developer testing and CI test suites.
"""

import os
from pathlib import Path
from typing import AsyncGenerator
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from .models import Base


def get_database_url() -> str:
    explicit = os.getenv("DATABASE_URL")
    if explicit:
        url = explicit
    else:
        custom_data = os.getenv("AUTOMAIL_DATA_DIR")
        if custom_data:
            db_path = Path(custom_data) / "automail_test.db"
            url = f"sqlite+aiosqlite:///{db_path.as_posix()}"
        else:
            url = "sqlite+aiosqlite:///./email_service/data/automail_dev.db"

    # Normalize postgres:// to postgresql+asyncpg:// if provided by cloud platforms
    if url.startswith("postgres://"):
        url = url.replace("postgres://", "postgresql+asyncpg://", 1)
    elif url.startswith("postgresql://") and "+asyncpg" not in url:
        url = url.replace("postgresql://", "postgresql+asyncpg://", 1)
    return url


def create_engine_and_factory():
    db_url = get_database_url()
    kwargs = {"echo": False}
    if "sqlite" in db_url:
        kwargs["connect_args"] = {"check_same_thread": False}
    else:
        kwargs["pool_size"] = int(os.getenv("DB_POOL_SIZE", "10"))
        kwargs["max_overflow"] = int(os.getenv("DB_MAX_OVERFLOW", "20"))
        kwargs["pool_recycle"] = 3600
        kwargs["pool_pre_ping"] = True
    eng = create_async_engine(db_url, **kwargs)
    factory = async_sessionmaker(
        bind=eng,
        class_=AsyncSession,
        expire_on_commit=False,
        autoflush=False
    )
    return eng, factory


async_engine, AsyncSessionLocal = create_engine_and_factory()


def reset_engine():
    """Recreate engine and session factory dynamically (used when AUTOMAIL_DATA_DIR changes)."""
    global async_engine, AsyncSessionLocal
    async_engine, AsyncSessionLocal = create_engine_and_factory()
    return async_engine, AsyncSessionLocal


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
