"""Async SQLAlchemy engine/session and declarative base.

SQLite (aiosqlite) is the local default; docker-compose switches to Postgres
via CASA_DATABASE_URL. Both drivers share the same async API.
"""
from __future__ import annotations

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase

from agent.core.config import settings


class Base(DeclarativeBase):
    pass


def _engine_kwargs(url: str) -> dict:
    if url.startswith("sqlite"):
        return {"connect_args": {"check_same_thread": False}}
    return {"pool_pre_ping": True}


def make_engine(database_url: str | None = None) -> AsyncEngine:
    url = database_url or settings.database_url
    return create_async_engine(url, echo=False, **_engine_kwargs(url))


engine = make_engine()

AsyncSessionLocal: async_sessionmaker[AsyncSession] = async_sessionmaker(
    engine, expire_on_commit=False, autoflush=False
)


async def get_session() -> AsyncSession:
    """FastAPI dependency: one session per request."""
    async with AsyncSessionLocal() as session:
        yield session
