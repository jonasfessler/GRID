"""
routers/advisories.py — Endpoints for the GRIDd/advisories collection.

Performance overview
--------------------
• Every list request uses a single $facet aggregation that delivers both the
  data page and the total count in **one MongoDB round-trip** (previously two).
• Filters that would previously trigger full-collection regex scans now hit
  dedicated compound indexes defined in database.ensure_indexes().
• Full-text search uses MongoDB's $text operator with a weighted text index
  (cve_id > title > description) instead of an unindexed $or/$regex chain.
• Fuzzy mode fetches up to 500 candidate documents and re-ranks them in Python
  using rapidfuzz, enabling typo-tolerant queries without Atlas Search.

New filters compared with the original API
-------------------------------------------
  published_after / published_before   — ISO-8601 date range on publication date
  modified_after  / modified_before    — ISO-8601 date range on last-modified date
  min_epss / max_epss                  — EPSS probability score range (0.0–1.0)
  has_fix                              — Boolean: requires non-empty fixed_versions
  severity                             — Substring match on metrics.severity_text
  exploitation_status                  — Substring match on metrics.exploitation_status
  cve_ids                              — Comma-separated bulk CVE-ID lookup
  fuzzy                                — Enable fuzzy re-ranking of text search results
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import List, Optional

from bson import ObjectId
from fastapi import APIRouter, HTTPException, Query, status

from API.database import col_advisories
from API.models import Advisory
from API.utils import (
    ADV_SORT_FIELDS,
    build_pagination_meta,
    doc_to_model,
    resolve_sort,
    serialize_doc,
)

# Lazy import — rapidfuzz is optional; if missing fuzzy=True returns a 422.
try:
    from rapidfuzz import fuzz as _rfuzz
    _FUZZY_AVAILABLE = True
except ImportError:  # pragma: no cover
    _FUZZY_AVAILABLE = False

router = APIRouter(prefix="/advisories", tags=["Advisories"])

# ---------------------------------------------------------------------------
# Projection used for list views (keeps payload lean)
# ---------------------------------------------------------------------------

_LIST_PROJECTION: dict = {
    "_id": 1,
    "cve_id": 1,
    "title": 1,
    "description": 1,
    "metrics": 1,
    "timeline": 1,
    "remediation": 1,
    "metadata": 1,
    "infrastructure.affected_os": 1,
}

# Minimum fuzzy score to include a result (0–100)
_FUZZY_MIN_SCORE = 40
# Max candidates fetched from MongoDB before fuzzy re-ranking
_FUZZY_CANDIDATE_CAP = 500


# ---------------------------------------------------------------------------
# Filter builder
# ---------------------------------------------------------------------------

def _build_filter(
    *,
    min_cvss: Optional[float],
    max_cvss: Optional[float],
    vendor_name: Optional[str],
    product_name: Optional[str],
    source: Optional[str],
    os_filter: Optional[str],
    remediation_status: Optional[str],
    search: Optional[str],
    cve_ids: Optional[str],
    published_after: Optional[datetime],
    published_before: Optional[datetime],
    modified_after: Optional[datetime],
    modified_before: Optional[datetime],
    min_epss: Optional[float],
    max_epss: Optional[float],
    has_fix: Optional[bool],
    severity: Optional[str],
    exploitation_status: Optional[str],
) -> dict:
    flt: dict = {}

    # ── CVSS range ───────────────────────────────────────────────────────────
    if min_cvss is not None or max_cvss is not None:
        cond: dict = {}
        if min_cvss is not None:
            cond["$gte"] = min_cvss
        if max_cvss is not None:
            cond["$lte"] = max_cvss
        flt["metrics.cvss_v3.base_score"] = cond

    # ── EPSS range ───────────────────────────────────────────────────────────
    if min_epss is not None or max_epss is not None:
        cond = {}
        if min_epss is not None:
            cond["$gte"] = min_epss
        if max_epss is not None:
            cond["$lte"] = max_epss
        flt["metrics.epss"] = cond

    # ── Vendor / product (array element match) ────────────────────────────
    if vendor_name:
        flt["infrastructure.affected_versions.vendor"] = {
            "$regex": re.escape(vendor_name), "$options": "i",
        }
    if product_name:
        flt["infrastructure.affected_versions.product"] = {
            "$regex": re.escape(product_name), "$options": "i",
        }

    # ── Source ───────────────────────────────────────────────────────────────
    if source:
        flt["metadata.sources"] = source.lower()

    # ── Affected OS ──────────────────────────────────────────────────────────
    if os_filter:
        flt["infrastructure.affected_os"] = {
            "$regex": re.escape(os_filter), "$options": "i",
        }

    # ── Remediation status ───────────────────────────────────────────────────
    if remediation_status:
        flt["remediation.status"] = {
            "$regex": re.escape(remediation_status), "$options": "i",
        }

    # ── Severity text ─────────────────────────────────────────────────────
    if severity:
        flt["metrics.severity_text"] = {
            "$regex": re.escape(severity), "$options": "i",
        }

    # ── Exploitation status ──────────────────────────────────────────────────
    if exploitation_status:
        flt["metrics.exploitation_status"] = {
            "$regex": re.escape(exploitation_status), "$options": "i",
        }

    # ── Has fix ──────────────────────────────────────────────────────────────
    # Uses positional index check: if index 0 exists, the array is non-empty.
    if has_fix is True:
        flt["remediation.fixed_versions.0"] = {"$exists": True}
    elif has_fix is False:
        flt["remediation.fixed_versions.0"] = {"$exists": False}

    # ── Date ranges (ISO-8601 strings sort lexicographically) ─────────────
    if published_after or published_before:
        cond = {}
        if published_after:
            cond["$gte"] = published_after.isoformat()
        if published_before:
            cond["$lte"] = published_before.isoformat()
        flt["timeline.published_at"] = cond

    if modified_after or modified_before:
        cond = {}
        if modified_after:
            cond["$gte"] = modified_after.isoformat()
        if modified_before:
            cond["$lte"] = modified_before.isoformat()
        flt["timeline.modified_at"] = cond

    # ── Bulk CVE-ID lookup ───────────────────────────────────────────────────
    if cve_ids:
        ids = [c.strip().upper() for c in cve_ids.split(",") if c.strip()]
        if ids:
            flt["cve_id"] = {"$in": ids}

    # ── Full-text search ($text — requires text index, see database.py) ──────
    # $text is used instead of the previous unindexed $or/$regex chain.
    # It is weighted: cve_id(10) > title(5) > description(1).
    if search:
        flt["$text"] = {"$search": search}

    return flt


# ---------------------------------------------------------------------------
# Fuzzy re-ranking (applied in Python after initial DB fetch)
# ---------------------------------------------------------------------------

def _fuzzy_rank(query: str, docs: list[dict]) -> list[dict]:
    """
    Score each document against *query* using rapidfuzz and return documents
    sorted by descending score, filtered by _FUZZY_MIN_SCORE.
    """
    q = query.lower()
    scored: list[tuple[int, dict]] = []
    for doc in docs:
        title   = (doc.get("title") or "").lower()
        cve_id  = (doc.get("cve_id") or "").lower()
        desc    = (doc.get("description") or "")[:400].lower()

        score = max(
            _rfuzz.partial_ratio(q, title),
            _rfuzz.partial_ratio(q, cve_id),
            _rfuzz.token_set_ratio(q, desc),
        )
        if score >= _FUZZY_MIN_SCORE:
            scored.append((score, doc))

    scored.sort(key=lambda x: -x[0])
    return [d for _, d in scored]


# ---------------------------------------------------------------------------
# GET /API/advisories/
# ---------------------------------------------------------------------------

@router.get(
    "/",
    response_model=dict,
    summary="List advisories",
    description=(
        "Returns a paginated list of processed vulnerability advisories from GRIDd.  \n\n"
        "**Performance:** count + data arrive in a single MongoDB round-trip via `$facet`.  \n\n"
        "**Search:** the `search` parameter uses a weighted MongoDB text index "
        "(CVE-ID > title > description) — far faster than the previous regex scan.  \n\n"
        "**Fuzzy mode** (`fuzzy=true`): fetches up to 500 candidates from MongoDB, "
        "then re-ranks them with rapidfuzz. Best for autocomplete / typo-tolerant queries. "
        "Deep pagination is not meaningful in fuzzy mode."
    ),
)
async def list_advisories(
    # ── Pagination ─────────────────────────────────────────────────────────
    page: int = Query(1, ge=1, description="Page number (1-indexed)."),
    page_size: int = Query(25, ge=1, le=200, description="Results per page (max 200)."),

    # ── CVSS / EPSS score filters ──────────────────────────────────────────
    min_cvss: Optional[float] = Query(None, ge=0.0, le=10.0, description="CVSS base score ≥ value."),
    max_cvss: Optional[float] = Query(None, ge=0.0, le=10.0, description="CVSS base score ≤ value."),
    min_epss: Optional[float] = Query(None, ge=0.0, le=1.0,  description="EPSS probability ≥ value."),
    max_epss: Optional[float] = Query(None, ge=0.0, le=1.0,  description="EPSS probability ≤ value."),

    # ── Entity filters ─────────────────────────────────────────────────────
    vendor_name: Optional[str] = Query(None, description="Case-insensitive substring match on vendor name."),
    product_name: Optional[str] = Query(None, description="Case-insensitive substring match on product name."),
    source: Optional[str] = Query(None, description="Ingest source: `csaf` or `euvd`."),
    affected_os: Optional[str] = Query(None, description="Case-insensitive substring match on affected OS."),

    # ── Remediation / severity filters ─────────────────────────────────────
    remediation_status: Optional[str] = Query(None, description="Substring match on remediation.status."),
    has_fix: Optional[bool] = Query(None, description="`true` = has fixed versions, `false` = none."),
    severity: Optional[str] = Query(None, description="Substring match on metrics.severity_text (e.g. 'kritisch')."),
    exploitation_status: Optional[str] = Query(None, description="Substring match on metrics.exploitation_status."),

    # ── Date range filters ─────────────────────────────────────────────────
    published_after:  Optional[datetime] = Query(None, description="Published at or after this ISO-8601 datetime."),
    published_before: Optional[datetime] = Query(None, description="Published at or before this ISO-8601 datetime."),
    modified_after:   Optional[datetime] = Query(None, description="Modified at or after this ISO-8601 datetime."),
    modified_before:  Optional[datetime] = Query(None, description="Modified at or before this ISO-8601 datetime."),

    # ── Bulk CVE lookup ────────────────────────────────────────────────────
    cve_ids: Optional[str] = Query(
        None,
        description="Comma-separated list of CVE IDs for bulk lookup, e.g. `CVE-2025-1234,CVE-2026-5678`.",
    ),

    # ── Full-text / fuzzy search ───────────────────────────────────────────
    search: Optional[str] = Query(
        None,
        description="Full-text search across cve_id, title, and description (uses a weighted text index).",
    ),
    fuzzy: bool = Query(
        False,
        description=(
            "Enable fuzzy/typo-tolerant re-ranking with rapidfuzz. "
            "Requires `search`. Deep pagination is approximate in this mode."
        ),
    ),

    # ── Sorting ────────────────────────────────────────────────────────────
    sort_by: str = Query(
        "timeline.published_at",
        description=(
            "Field to sort by. Allowed values: "
            "`timeline.published_at`, `timeline.modified_at`, "
            "`metrics.cvss_v3.base_score`, `metrics.epss`, `cve_id`, `title`. "
            "Prefix with `-` for descending (default for most fields). "
            "When `search` is active, prefix with `relevance` to rank by text score."
        ),
    ),
) -> dict:

    if fuzzy and not search:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="`fuzzy=true` requires a `search` term.",
        )
    if fuzzy and not _FUZZY_AVAILABLE:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="rapidfuzz is not installed on this server; fuzzy search is unavailable.",
        )

    flt = _build_filter(
        min_cvss=min_cvss, max_cvss=max_cvss,
        vendor_name=vendor_name, product_name=product_name,
        source=source, os_filter=affected_os,
        remediation_status=remediation_status,
        search=search, cve_ids=cve_ids,
        published_after=published_after, published_before=published_before,
        modified_after=modified_after, modified_before=modified_before,
        min_epss=min_epss, max_epss=max_epss,
        has_fix=has_fix, severity=severity,
        exploitation_status=exploitation_status,
    )

    # ── Sorting ─────────────────────────────────────────────────────────────
    text_active = "$text" in flt
    use_text_sort = text_active and sort_by.lstrip("-") == "relevance"

    sort_field, sort_dir = resolve_sort(sort_by, ADV_SORT_FIELDS, "timeline.published_at")

    skip = (page - 1) * page_size

    # In fuzzy mode: bypass pagination — fetch all candidates, rank in Python
    mongo_skip  = 0          if fuzzy else skip
    mongo_limit = min(_FUZZY_CANDIDATE_CAP, page_size * 10) if fuzzy else page_size

    col = col_advisories()

    # ── Build aggregation pipeline ──────────────────────────────────────────
    # Single round-trip via $facet: one branch counts, the other retrieves data.
    pipeline: list[dict] = []

    # Stage 1 — filter
    pipeline.append({"$match": flt})

    # Stage 2 — materialise text-relevance score (only when $text is active)
    if text_active:
        pipeline.append({"$addFields": {"_score": {"$meta": "textScore"}}})

    # Stage 3 — $facet: count + paginated data in one shot
    sort_doc: dict
    if use_text_sort:
        sort_doc = {"_score": -1}
    else:
        sort_doc = {sort_field: sort_dir}
        # Secondary sort by text score when search is active (breaks score ties)
        if text_active:
            sort_doc["_score"] = -1

    data_pipeline: list[dict] = [
        {"$sort": sort_doc},
        {"$skip": mongo_skip},
        {"$limit": mongo_limit},
        {"$project": {**_LIST_PROJECTION}},   # _score excluded implicitly
    ]

    pipeline.append({
        "$facet": {
            "meta":  [{"$count": "total"}],
            "items": data_pipeline,
        }
    })

    raw = await col.aggregate(pipeline, allowDiskUse=True).to_list(1)
    facet  = raw[0] if raw else {"meta": [], "items": []}
    total  = facet["meta"][0]["total"] if facet["meta"] else 0
    docs   = facet["items"]

    # ── Fuzzy post-processing ───────────────────────────────────────────────
    if fuzzy and search and docs:
        ranked = _fuzzy_rank(search, docs)
        total  = len(ranked)          # total is now the fuzzy-filtered count
        docs   = ranked[skip : skip + page_size]

    # ── Serialise ──────────────────────────────────────────────────────────
    items: List[dict] = [serialize_doc(doc) for doc in docs]

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
