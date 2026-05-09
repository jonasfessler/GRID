"""
main.py — GRID API: Central FastAPI entry point.

Start with:
    uvicorn API.main:app --reload --host 0.0.0.0 --port 8000

Swagger UI:  http://localhost:8000/API/docs
ReDoc:       http://localhost:8000/API/redoc
OpenAPI JSON: http://localhost:8000/API/openapi.json
"""

from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from API.database import col_metadata, connect_db, close_db
from API.models import IngestStatus
from API.routers import advisories, products, vendors


# ---------------------------------------------------------------------------
# Lifespan — DB connect / disconnect
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage the async MongoDB client lifecycle."""
    await connect_db()
    yield
    await close_db()


# ---------------------------------------------------------------------------
# Application factory
# ---------------------------------------------------------------------------

app = FastAPI(
    title="GRID API — Global Risk Intelligence Dashboard",
    version="1.0.0",
    description=(
        "Asynchronous REST API serving processed vulnerability data from the **GRIDd** "
        "(GRID-Data) MongoDB database.  \n\n"
        "The data originates from two raw ingest sources:\n"
        "- **CERT-BUND** (CSAF advisory format)\n"
        "- **ENISA EUVD** (EU Vulnerability Database)\n\n"
        "Data flows through the Medallion architecture: `GRIDr` (raw) → join/enrich pipeline → `GRIDd` (processed)."
    ),
    docs_url="/API/docs",
    redoc_url="/API/redoc",
    openapi_url="/API/openapi.json",
    lifespan=lifespan,
    contact={
        "name": "GRID Project",
    },
    license_info={
        "name": "Internal Use",
    },
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
# Routers — all mounted under /API
# ---------------------------------------------------------------------------

API_PREFIX = "/API"

app.include_router(advisories.router, prefix=API_PREFIX)
app.include_router(products.router,   prefix=API_PREFIX)
app.include_router(vendors.router,    prefix=API_PREFIX)


# ---------------------------------------------------------------------------
# Status endpoint
# ---------------------------------------------------------------------------

@app.get(
    "/API/status",
    response_model=IngestStatus,
    tags=["Status"],
    summary="API & ingest status",
    description=(
        "Returns collection counts for advisories, products, and vendors, "
        "plus the most recent metadata record from the processing pipeline."
    ),
)
async def get_status() -> IngestStatus:
    from API.database import col_advisories, col_products, col_vendors

    advisory_count = await col_advisories().estimated_document_count()
    product_count  = await col_products().estimated_document_count()
    vendor_count   = await col_vendors().estimated_document_count()

    # Fetch most recent metadata entry (sorted by timestamp descending)
    last_meta_doc = await col_metadata().find_one(
        {}, sort=[("timestamp", -1)]
    )
    last_ingest: dict | None = None
    if last_meta_doc:
        last_meta_doc["_id"] = str(last_meta_doc["_id"])
        last_ingest = last_meta_doc

    return IngestStatus(
        advisory_count=advisory_count,
        product_count=product_count,
        vendor_count=vendor_count,
        last_ingest=last_ingest,
    )


# ---------------------------------------------------------------------------
# Root redirect
# ---------------------------------------------------------------------------

@app.get("/", include_in_schema=False)
async def root() -> JSONResponse:
    return JSONResponse(
        content={
            "message": "GRID API is running.",
            "docs":    "/API/docs",
            "status":  "/API/status",
        }
    )
