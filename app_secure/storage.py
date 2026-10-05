"""Local PostgreSQL access for the secure application

The local ``db`` service receives a standard PostgreSQL dump from Neon
"""

import os

import psycopg
from psycopg.rows import dict_row


USER_TABLE_SCHEMA = """
CREATE TABLE IF NOT EXISTS public.users (
    id BIGSERIAL PRIMARY KEY,
    name TEXT NOT NULL,
    email TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user',
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
)
"""

USER_SELECT = """
    SELECT
        'public:' || id::text AS id,
        COALESCE(NULLIF(name, ''), email) AS username,
        email,
        password_hash,
        CASE WHEN lower(role) = 'admin' THEN 'admin' ELSE 'user' END AS role,
        true AS is_active,
        false AS password_reset_required
    FROM public.users
"""


def connect():
    """open the local PostgreSQL connection used by the secure app"""
    database_url = os.getenv("LOCAL_DATABASE_URL")
    if database_url:
        return psycopg.connect(database_url, row_factory=dict_row)

    return psycopg.connect(
        host=os.getenv("LOCAL_DB_HOST", "db"),
        port=int(os.getenv("LOCAL_DB_PORT", "5432")),
        dbname=os.getenv("LOCAL_DB_NAME", "cyberlab"),
        user=os.getenv("LOCAL_DB_USER", "cyberlab"),
        password=os.getenv("LOCAL_DB_PASSWORD", "change-me-local-only"),
        row_factory=dict_row,
    )


def initialize_database() -> None:
    """Create the minimal local table if the dump has not been restored yet."""
    # from Neon
    with connect() as connection:
        connection.execute(USER_TABLE_SCHEMA)


def get_user(identifier: str) -> dict | None:
    initialize_database()
    with connect() as connection:
        row = connection.execute(
            USER_SELECT + " WHERE name = %s OR email = %s",
            (identifier, identifier),
        ).fetchone()
    return dict(row) if row else None


def get_user_by_id(user_id: str) -> dict | None:
    prefix, separator, raw_id = user_id.partition(":")
    if prefix != "public" or not separator or not raw_id.isdigit():
        return None

    initialize_database()
    with connect() as connection:
        row = connection.execute(
            USER_SELECT + " WHERE id = %s",
            (int(raw_id),),
        ).fetchone()
    return dict(row) if row else None

