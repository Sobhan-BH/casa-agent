"""Lightweight idempotent migrations for schema evolution.

`Base.metadata.create_all` creates missing TABLES but never ALTERs existing
ones, so a database created before a new column was introduced fails on
startup with "no such column". This module adds the known missing columns
safely: each addition is checked against the live table first and skipped if
it already exists, so it is safe to run on every startup.

Supported: SQLite (ALTER TABLE ADD COLUMN), PostgreSQL (same via psycopg).
This is deliberately not Alembic — the MVP schema surface is tiny; upgrade to
Alembic when the schema churn grows.
"""
from __future__ import annotations

import logging

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection

logger = logging.getLogger("casa.migrations")

# (table, column, DDL) — DDL must be valid for BOTH SQLite and Postgres.
_ADD_COLUMNS: list[tuple[str, str, str]] = [
    ("jobs", "profile", "VARCHAR(16) DEFAULT 'STANDARD'"),
    ("assessments", "attack_surface", "JSON NULL"),
]

_ADD_INDEXES: list[tuple[str, str]] = [
    # (table, column) — index name is derived deterministically.
    ("findings", "dedupe_key"),
]


def _quote_ident(name: str) -> str:
    """Basic identifier quoting; names are internal constants, not user input."""
    if not name.replace("_", "").isalnum():
        raise ValueError(f"unsafe identifier: {name!r}")
    return f'"{name}"'


async def run_migrations(conn: AsyncConnection) -> list[str]:
    """Apply pending column/index additions; returns applied change names."""
    applied: list[str] = []

    for table, column, ddl in _ADD_COLUMNS:
        if conn.dialect.name == "postgresql":
            exists = await conn.execute(
                text(
                    "SELECT 1 FROM information_schema.columns "
                    "WHERE table_name = :t AND column_name = :c"
                ),
                {"t": table, "c": column},
            )
        else:
            # pragma_table_info is a table-valued function: SQLite does not
            # accept bind parameters in that position, so the (internally
            # validated, constant) identifiers are inlined as literals.
            exists = await conn.execute(
                text(
                    f"SELECT 1 FROM pragma_table_info('{table}') "
                    f"WHERE name = '{column}'"
                )
            )
        if exists.first() is None:
            await conn.execute(
                text(f"ALTER TABLE {_quote_ident(table)} ADD COLUMN "
                     f"{_quote_ident(column)} {ddl}")
            )
            applied.append(f"{table}.{column}")

    for table, column in _ADD_INDEXES:
        idx_name = f"ix_{table}_{column}"
        if conn.dialect.name == "postgresql":
            exists = await conn.execute(
                text("SELECT 1 FROM pg_indexes WHERE indexname = :i"),
                {"i": idx_name},
            )
        else:
            exists = await conn.execute(
                text(
                    f"SELECT 1 FROM sqlite_master WHERE type='index' "
                    f"AND name = '{idx_name}'"
                )
            )
        if exists.first() is None:
            await conn.execute(
                text(
                    f'CREATE INDEX IF NOT EXISTS {idx_name} '
                    f'ON {_quote_ident(table)} ({_quote_ident(column)})'
                )
            )
            applied.append(f"index:{idx_name}")

    if applied:
        logger.info("applied migrations: %s", ", ".join(applied))
    return applied
