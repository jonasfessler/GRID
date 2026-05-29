"""
database.py — Async MongoDB connection, collection accessors, and index management.

Uses motor (AsyncIOMotorClient) so every DB call is non-blocking and plays
well with FastAPI's event loop.
"""

import os
import logging

from motor.motor_asyncio import (
    AsyncIOMotorClient,
    AsyncIOMotorDatabase,
    AsyncIOMotorCollection,
)

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration — override via environment variables in production
# ---------------------------------------------------------------------------

MONGO_URI: str = os.getenv("MONGO_URI", "mongodb://localhost:27017")
DB_NAME: str   = os.getenv("GRIDD_DB", "GRIDd")

# ---------------------------------------------------------------------------
# Module-level client (initialised on startup, reused across all requests)
# ---------------------------------------------------------------------------

_client: AsyncIOMotorClient | None = None


def get_client() -> AsyncIOMotorClient:
    """Return the singleton motor client, creating it if needed."""
    global _client
    if _client is None:
        _client = AsyncIOMotorClient(
            MONGO_URI,
            # Tune the connection pool for a FastAPI workload:
            maxPoolSize=20,        # max concurrent connections
            minPoolSize=5,         # keep warm connections alive
            serverSelectionTimeoutMS=5_000,
            connectTimeoutMS=5_000,
            socketTimeoutMS=30_000,
        )
    return _client


def get_database() -> AsyncIOMotorDatabase:
    """Return the GRIDd database handle."""
    return get_client()[DB_NAME]


# ---------------------------------------------------------------------------
# Collection helpers
# ---------------------------------------------------------------------------

def col_advisories() -> AsyncIOMotorCollection:
    return get_database()["advisories"]

def col_products() -> AsyncIOMotorCollection:
    return get_database()["products"]

def col_vendors() -> AsyncIOMotorCollection:
    return get_database()["vendors"]

def col_metadata() -> AsyncIOMotorCollection:
    return get_database()["metadata"]


# ---------------------------------------------------------------------------
# Index management — called once at startup
# ---------------------------------------------------------------------------

async def ensure_indexes() -> None:
    """
    Create all performance-critical indexes for GRIDd collections.

    MongoDB is idempotent on index creation (no-ops if the index already
    exists with the same key/options), so this is safe to call on every
    startup without side effects.
    """
    adv  = col_advisories()
    prod = col_products()
    vend = col_vendors()

    # ── Advisories ──────────────────────────────────────────────────────────

    # Full-text search index (used by the $text operator).
    # Weights make CVE-ID matches rank highest, titles second, descriptions last.
    # default_language "none" disables language-specific stemming, which keeps
    # CVE IDs intact and works across the German/English advisory mix.
    await adv.create_index(
        [("cve_id", "text"), ("title", "text"), ("description", "text")],
        name="adv_text",
        weights={"cve_id": 10, "title": 5, "description": 1},
        default_language="none",
    )

    # Individual field indexes used by the most common filter combos
    await adv.create_index([("metrics.cvss_v3.base_score", 1)],  name="adv_cvss",           sparse=True)
    await adv.create_index([("metrics.epss", 1)],                name="adv_epss",           sparse=True)
    await adv.create_index([("timeline.published_at", -1)],      name="adv_published_desc")
    await adv.create_index([("timeline.modified_at",  -1)],      name="adv_modified_desc")
    await adv.create_index( "metadata.sources",                  name="adv_sources")
    await adv.create_index( "infrastructure.affected_versions.vendor",  name="adv_vendor")
    await adv.create_index( "infrastructure.affected_versions.product", name="adv_product")
    await adv.create_index( "infrastructure.affected_os",        name="adv_os")
    await adv.create_index( "remediation.status",                name="adv_remediation_status")
    await adv.create_index( "metrics.severity_text",             name="adv_severity",  sparse=True)
    await adv.create_index( "metrics.exploitation_status",       name="adv_exploit",   sparse=True)

    # Compound: covers the most common dashboard query — high-severity, recent
    await adv.create_index(
        [("metrics.cvss_v3.base_score", -1), ("timeline.published_at", -1)],
        name="adv_cvss_date",
    )

    # ── Products ─────────────────────────────────────────────────────────────

    await prod.create_index(
        [("name", "text"), ("vendor_name", "text"), ("raw_names", "text")],
        name="prod_text",
        weights={"name": 5, "vendor_name": 3, "raw_names": 1},
        default_language="none",
    )
    await prod.create_index("vendor_name", name="prod_vendor")
    await prod.create_index("sources",     name="prod_sources")

    # ── Vendors ──────────────────────────────────────────────────────────────

    await vend.create_index(
        [("name", "text"), ("raw_names", "text")],
        name="vend_text",
        weights={"name": 10, "raw_names": 1},
        default_language="none",
    )
    await vend.create_index("name",    name="vend_name")
    await vend.create_index("sources", name="vend_sources")

    log.info("GRIDd indexes verified / created.")


# ---------------------------------------------------------------------------
# Lifecycle helpers (called from main.py startup / shutdown events)
# ---------------------------------------------------------------------------

async def connect_db() -> None:
    """Ping MongoDB on startup to surface connection problems early."""
    client = get_client()
    await client.admin.command("ping")
    log.info("MongoDB connection established.")


async def close_db() -> None:
    """Gracefully close the motor client on shutdown."""
    global _client
    if _client is not None:
        _client.close()
        _client = None
        log.info("MongoDB connection closed.")
