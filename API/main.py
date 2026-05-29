"""
main.py — GRID API: Central FastAPI entry point.

Start with:
    uvicorn API.main:app --reload --host 0.0.0.0 --port 8000

Swagger UI:   http://localhost:8000/API/docs
ReDoc:        http://localhost:8000/API/redoc
OpenAPI JSON: http://localhost:8000/API/openapi.json
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from API.database import (
    close_db,
    col_advisories,
    col_metadata,
    col_products,
    col_vendors,
    connect_db,
    ensure_indexes,
)
from API.models import IngestStatus
from API.routers import advisories, products, vendors
from API.utils import TTLCache

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# TTL cache for the /status endpoint (4 DB calls → cache hit after first req)
# ---------------------------------------------------------------------------

_status_cache = TTLCache(ttl=60.0)   # refresh every 60 s


# ---------------------------------------------------------------------------
# Lifespan — DB connect / index creation / disconnect
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage the async MongoDB client lifecycle."""
    await connect_db()
    await ensure_indexes()   # idempotent — safe on every restart
    yield
    await close_db()


# ---------------------------------------------------------------------------
# Application factory
# ---------------------------------------------------------------------------

app = FastAPI(
    title="GRID API — Global Risk Intelligence Dashboard",
    version="2.0.0",
    description=(
        "Asynchronous REST API serving processed vulnerability data from the **GRIDd** "
        "(GRID-Data) MongoDB database.  \n\n"
        "The data originates from two raw ingest sources:\n"
        "- **CERT-BUND** (CSAF advisory format)\n"
        "- **ENISA EUVD** (EU Vulnerability Database)\n\n"
        "Data flows through the Medallion architecture: `GRIDr` (raw) → join/enrich pipeline → `GRIDd` (processed).  \n\n"
        "### v2.0 performance notes\n"
        "- All list endpoints use a single `$facet` aggregation (one round-trip instead of two).\n"
        "- Full-text search uses a weighted MongoDB text index — no more full-collection regex scans.\n"
        "- All filter fields are backed by dedicated MongoDB indexes created at startup.\n"
        "- `/API/status` responses are cached for 60 s.\n"
        "- Fuzzy search (rapidfuzz) available for advisory queries."
    ),
    docs_url="/API/docs",
    redoc_url="/API/redoc",
    openapi_url="/API/openapi.json",
    lifespan=lifespan,
    contact={"name": "GRID Project"},
    license_info={"name": "GPL-3.0"},
)

# ---------------------------------------------------------------------------
# CORS — open for development; tighten in production
# ---------------------------------------------------------------------------

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Routers
# ---------------------------------------------------------------------------

API_PREFIX = "/API"

app.include_router(advisories.router, prefix=API_PREFIX)
app.include_router(products.router,   prefix=API_PREFIX)
app.include_router(vendors.router,    prefix=API_PREFIX)


# ---------------------------------------------------------------------------
# Status endpoint  (cached)
# ---------------------------------------------------------------------------

async def _fetch_status() -> dict:
    """Compute fresh status data from MongoDB."""
    advisory_count = await col_advisories().estimated_document_count()
    product_count  = await col_products().estimated_document_count()
    vendor_count   = await col_vendors().estimated_document_count()

    last_meta_doc = await col_metadata().find_one(
        {}, sort=[("timestamp", -1)]
    )
    last_ingest: dict | None = None
    if last_meta_doc:
        last_meta_doc["_id"] = str(last_meta_doc["_id"])
        last_ingest = last_meta_doc

    return {
        "advisory_count": advisory_count,
        "product_count":  product_count,
        "vendor_count":   vendor_count,
        "last_ingest":    last_ingest,
    }


@app.get(
    "/API/status",
    response_model=IngestStatus,
    tags=["Status"],
    summary="API & ingest status",
    description=(
        "Returns collection counts for advisories, products, and vendors, "
        "plus the most recent metadata record from the processing pipeline.  \n\n"
        "Response is cached for **60 seconds** to avoid hammering MongoDB on "
        "high-traffic dashboards."
    ),
)
async def get_status() -> IngestStatus:
    data = await _status_cache.get_or_set("status", _fetch_status)
    return IngestStatus(**data)


# ---------------------------------------------------------------------------
# Root redirect
# ---------------------------------------------------------------------------

@app.get("/", include_in_schema=False)
async def root() -> JSONResponse:
    return JSONResponse(
        content={
            "message": "GRID API v2 is running.",
            "docs":    "/API/docs",
            "status":  "/API/status",
        }
    )
