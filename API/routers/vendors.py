"""
routers/vendors.py — Endpoints for the GRIDd/vendors collection.

Changes vs. original
---------------------
• List endpoint uses a single $facet aggregation (one round-trip).
• Added `search` param backed by a weighted text index.
• Added explicit list projection (avoids pulling the raw_names array when not needed).
• `sort_by` validated against an allow-list.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import List, Optional

from bson import ObjectId
from fastapi import APIRouter, HTTPException, Query, status

from API.database import col_vendors
from API.models import Vendor
from API.utils import (
    VEND_SORT_FIELDS,
    build_pagination_meta,
    doc_to_model,
    resolve_sort,
)

router = APIRouter(prefix="/vendors", tags=["Vendors"])

# List view omits raw_names (can be a large array); available via /{id}
_LIST_PROJECTION: dict = {
    "_id": 1, "name": 1, "sources": 1, "created_at": 1, "updated_at": 1,
}


# ---------------------------------------------------------------------------
# GET /API/vendors/
# ---------------------------------------------------------------------------

@router.get(
    "/",
    response_model=dict,
    summary="List vendors",
    description=(
        "Returns a paginated, alphabetically sorted list of normalised vendors.  \n\n"
        "**Search:** the `search` parameter uses a weighted text index on `name` and `raw_names`. "
        "The `raw_names` array is excluded from list results; use `GET /API/vendors/{id}` to retrieve it."
    ),
)
async def list_vendors(
    page: int = Query(1, ge=1, description="Page number (1-indexed)."),
    page_size: int = Query(25, ge=1, le=200, description="Results per page (max 200)."),

    vendor_name: Optional[str] = Query(None, description="Case-insensitive substring match on canonical name."),
    source: Optional[str] = Query(None, description="Filter by ingest source: `csaf` or `euvd`."),

    search: Optional[str] = Query(
        None,
        description="Full-text search across name and raw_names (uses a weighted text index).",
    ),

    sort_by: str = Query(
        "name",
        description="Sort field. Allowed: `name`, `created_at`, `updated_at`. Prefix with `-` for descending.",
    ),
) -> dict:

    flt: dict = {}

    if search:
        flt["$text"] = {"$search": search}
    if vendor_name:
        flt["name"] = {"$regex": re.escape(vendor_name), "$options": "i"}
    if source:
        flt["sources"] = source.lower()

    sort_field, sort_dir = resolve_sort(sort_by, VEND_SORT_FIELDS, "name")
    text_active = "$text" in flt
    sort_doc: dict = {sort_field: sort_dir}
    if text_active:
        sort_doc["_score"] = -1

    skip = (page - 1) * page_size
    col  = col_vendors()

    pipeline: list[dict] = [{"$match": flt}]
    if text_active:
        pipeline.append({"$addFields": {"_score": {"$meta": "textScore"}}})

    data_pipe: list[dict] = [
        {"$sort": sort_doc},
        {"$skip": skip},
        {"$limit": page_size},
        {"$project": {**_LIST_PROJECTION, "_score": 0}},
    ]

    pipeline.append({
        "$facet": {
            "meta":  [{"$count": "total"}],
            "items": data_pipe,
        }
    })

    raw   = await col.aggregate(pipeline).to_list(1)
    facet = raw[0] if raw else {"meta": [], "items": []}
    total = facet["meta"][0]["total"] if facet["meta"] else 0

    items: List[dict] = []
    for doc in facet["items"]:
        doc["_id"] = str(doc["_id"])
        items.append(doc)

    return {
        "data": items,
        "pagination": build_pagination_meta(total, page, page_size),
    }


# ---------------------------------------------------------------------------
# GET /API/vendors/{object_id}
# ---------------------------------------------------------------------------

@router.get(
    "/{object_id}",
    response_model=Vendor,
    summary="Get vendor by ObjectId",
    description="Retrieve a single, full vendor document (including raw_names) by its MongoDB `_id`.",
)
async def get_vendor(object_id: str) -> Vendor:
    try:
        oid = ObjectId(object_id)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"'{object_id}' is not a valid ObjectId.",
        )
    col = col_vendors()
    doc = await col.find_one({"_id": oid})
    if doc is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No vendor found with _id '{object_id}'.",
        )
    return doc_to_model(doc, Vendor)
