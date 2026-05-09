"""
database.py — Async MongoDB connection & collection accessors for GRIDd.

Uses motor (AsyncIOMotorClient) so every DB call is non-blocking and plays
well with FastAPI's event-loop.
"""

import os
from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase, AsyncIOMotorCollection

# ---------------------------------------------------------------------------
# Configuration — override via environment variables in production
# ---------------------------------------------------------------------------

MONGO_URI: str = os.getenv("MONGO_URI", "mongodb://localhost:27017")
DB_NAME: str   = os.getenv("GRIDD_DB", "GRIDd")

# ---------------------------------------------------------------------------
# Module-level client (initialised on first import, reused across requests)
# ---------------------------------------------------------------------------

_client: AsyncIOMotorClient | None = None


def get_client() -> AsyncIOMotorClient:
    """Return the singleton motor client, creating it if needed."""
    global _client
    if _client is None:
        _client = AsyncIOMotorClient(MONGO_URI)
    return _client


def get_database() -> AsyncIOMotorDatabase:
    """Return the GRIDd database handle."""
    return get_client()[DB_NAME]


# ---------------------------------------------------------------------------
# Collection helpers — one function per collection for clean imports
# ---------------------------------------------------------------------------

def col_advisories() -> AsyncIOMotorCollection:
    """GRIDd / advisories collection."""
    return get_database()["advisories"]


def col_products() -> AsyncIOMotorCollection:
    """GRIDd / products collection."""
    return get_database()["products"]


def col_vendors() -> AsyncIOMotorCollection:
    """GRIDd / vendors collection."""
    return get_database()["vendors"]


def col_metadata() -> AsyncIOMotorCollection:
    """GRIDd / metadata collection (ingest run records)."""
    return get_database()["metadata"]


# ---------------------------------------------------------------------------
# Lifecycle helpers (called from main.py startup / shutdown events)
# ---------------------------------------------------------------------------

async def connect_db() -> None:
    """Ping MongoDB on startup to surface connection problems early."""
    client = get_client()
    await client.admin.command("ping")


async def close_db() -> None:
    """Gracefully close the motor client on shutdown."""
    global _client
    if _client is not None:
        _client.close()
        _client = None
