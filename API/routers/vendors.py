"""
routers/vendors.py — Endpoints for the GRIDd/vendors collection.
"""

from __future__ import annotations

from typing import List, Optional

from bson import ObjectId
from fastapi import APIRouter, HTTPException, Query, status

from API.database import col_vendors
from API.models import Vendor
from API.utils import doc_to_model, build_pagination_meta

router = APIRouter(
    prefix="/vendors",
    tags=["Vendors"],
)


# ---------------------------------------------------------------------------
# GET /API/vendors
# ---------------------------------------------------------------------------

@router.get(
    "/",
    response_model=dict,
    summary="List vendors",
    description=(
        "Returns a paginated, alphabetically sorted list of all normalised vendors. "
        "Use `vendor_name` to filter by a name substring."
    ),
)
async def list_vendors(
    page: int = Query(1, ge=1, description="Page number (1-indexed)."),
    page_size: int = Query(25, ge=1, le=200, description="Number of results per page (max 200)."),
    vendor_name: Optional[str] = Query(
        None,
        description="Case-insensitive substring match on the canonical `name` field.",
    ),
    source: Optional[str] = Query(None, description="Filter by ingest source: 'csaf' or 'euvd'."),
) -> dict:
    flt: dict = {}

    if vendor_name:
        flt["name"] = {"$regex": vendor_name, "$options": "i"}
    if source:
        flt["sources"] = source.lower()

    skip  = (page - 1) * page_size
    col   = col_vendors()
    total = await col.count_documents(flt)

    cursor = (
        col.find(flt)
        .sort("name", 1)
        .skip(skip)
        .limit(page_size)
    )

    items: List[dict] = []
    async for doc in cursor:
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
    description="Retrieve a single vendor document by its MongoDB `_id`.",
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
