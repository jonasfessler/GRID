"""
routers/advisories.py — Endpoints for the GRIDd/advisories collection.

All filter parameters are optional and can be freely combined.
"""

from __future__ import annotations

from typing import List, Optional

from bson import ObjectId
from fastapi import APIRouter, HTTPException, Query, status

from API.database import col_advisories
from API.models import Advisory
from API.utils import doc_to_model, build_pagination_meta

router = APIRouter(
    prefix="/advisories",
    tags=["Advisories"],
)


# ---------------------------------------------------------------------------
# Helper — build a MongoDB filter dict from query parameters
# ---------------------------------------------------------------------------

def _build_filter(
    min_cvss: Optional[float],
    max_cvss: Optional[float],
    vendor_name: Optional[str],
    product_name: Optional[str],
    source: Optional[str],
    os_filter: Optional[str],
    remediation_status: Optional[str],
    search: Optional[str] = None,
) -> dict:
    flt: dict = {}

    # CVSS score range
    if min_cvss is not None or max_cvss is not None:
        cvss_cond: dict = {}
        if min_cvss is not None:
            cvss_cond["$gte"] = min_cvss
        if max_cvss is not None:
            cvss_cond["$lte"] = max_cvss
        flt["metrics.cvss_v3.base_score"] = cvss_cond

    # Vendor / product (case-insensitive regex match inside affected_versions array)
    if vendor_name:
        flt["infrastructure.affected_versions.vendor"] = {
            "$regex": vendor_name,
            "$options": "i",
        }
    if product_name:
        flt["infrastructure.affected_versions.product"] = {
            "$regex": product_name,
            "$options": "i",
        }

    # Source filter (csaf | euvd)
    if source:
        flt["metadata.sources"] = source.lower()

    # Affected OS (case-insensitive contains)
    if os_filter:
        flt["infrastructure.affected_os"] = {"$regex": os_filter, "$options": "i"}

    # Remediation status (case-insensitive exact prefix)
    if remediation_status:
        flt["remediation.status"] = {"$regex": remediation_status, "$options": "i"}

    # Full-text search across title, description, and CVE ID
    if search:
        pattern = {"$regex": search, "$options": "i"}
        flt["$or"] = [
            {"title":       pattern},
            {"description": pattern},
            {"cve_id":      pattern},
        ]

    return flt


# ---------------------------------------------------------------------------
# GET /API/advisories
# ---------------------------------------------------------------------------

@router.get(
    "/",
    response_model=dict,
    summary="List advisories",
    description=(
        "Returns a paginated list of processed vulnerability advisories from GRIDd. "
        "All filter parameters are **optional** and may be freely combined."
    ),
)
async def list_advisories(
    # Pagination
    page: int = Query(1, ge=1, description="Page number (1-indexed)."),
    page_size: int = Query(25, ge=1, le=200, description="Number of results per page (max 200)."),
    # Score filters
    min_cvss: Optional[float] = Query(
        None, ge=0.0, le=10.0,
        description="Only return advisories with CVSS base score ≥ this value.",
    ),
    max_cvss: Optional[float] = Query(
        None, ge=0.0, le=10.0,
        description="Only return advisories with CVSS base score ≤ this value.",
    ),
    # Entity filters
    vendor_name: Optional[str] = Query(None, description="Case-insensitive substring match on vendor name."),
    product_name: Optional[str] = Query(None, description="Case-insensitive substring match on product name."),
    # Misc filters
    source: Optional[str] = Query(None, description="Filter by ingest source: 'csaf' or 'euvd'."),
    affected_os: Optional[str] = Query(None, description="Case-insensitive substring match on affected OS."),
    remediation_status: Optional[str] = Query(
        None,
        description="Filter by remediation status string, e.g. 'Patch available'.",
    ),
    # Full-text search
    search: Optional[str] = Query(
        None,
        description="Case-insensitive substring search across title, description, and CVE ID.",
    ),
    # Sorting
    sort_by: str = Query(
        "timeline.published_at",
        description="Field to sort by. Prefix with '-' for descending, e.g. '-metrics.cvss_v3.base_score'.",
    ),
) -> dict:
    flt = _build_filter(min_cvss, max_cvss, vendor_name, product_name, source, affected_os, remediation_status, search)

    # --- sorting ---
    descending = sort_by.startswith("-")
    sort_field  = sort_by.lstrip("-")
    sort_dir    = -1 if descending else 1

    skip   = (page - 1) * page_size
    col    = col_advisories()
    total  = await col.count_documents(flt)
    cursor = col.find(flt, {"_id": 1, "cve_id": 1, "title": 1, "description": 1,
                            "metrics": 1, "timeline": 1, "remediation": 1,
                            "metadata": 1, "infrastructure.affected_os": 1})
    cursor = cursor.sort(sort_field, sort_dir).skip(skip).limit(page_size)

    items: List[dict] = []
    async for doc in cursor:
        doc["_id"] = str(doc["_id"])
        items.append(doc)

    return {
        "data": items,
        "pagination": build_pagination_meta(total, page, page_size),
    }


# ---------------------------------------------------------------------------
# GET /API/advisories/{cve_id}
# ---------------------------------------------------------------------------

@router.get(
    "/{cve_id}",
    response_model=Advisory,
    summary="Get advisory by CVE-ID",
    description=(
        "Retrieve the full advisory document for a specific CVE identifier. "
        "CVE-IDs are case-sensitive, e.g. `CVE-2026-12345`."
    ),
)
async def get_advisory_by_cve(cve_id: str) -> Advisory:
    col = col_advisories()
    doc = await col.find_one({"cve_id": cve_id})
    if doc is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No advisory found for CVE-ID '{cve_id}'.",
        )
    return doc_to_model(doc, Advisory)


# ---------------------------------------------------------------------------
# GET /API/advisories/id/{object_id}
# ---------------------------------------------------------------------------

@router.get(
    "/id/{object_id}",
    response_model=Advisory,
    summary="Get advisory by MongoDB ObjectId",
    description="Retrieve a single advisory by its internal MongoDB `_id` (24-character hex string).",
)
async def get_advisory_by_id(object_id: str) -> Advisory:
    try:
        oid = ObjectId(object_id)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"'{object_id}' is not a valid ObjectId.",
        )
    col = col_advisories()
    doc = await col.find_one({"_id": oid})
    if doc is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No advisory found with _id '{object_id}'.",
        )
    return doc_to_model(doc, Advisory)
