"""
routers/products.py — Endpoints for the GRIDd/products collection.

Changes vs. original
---------------------
• List endpoint uses a single $facet aggregation (count + data, one round-trip).
• Added `search` param that uses a weighted text index (name, vendor_name, raw_names).
• Added `updated_after` / `updated_before` date range filters.
• List projection now explicitly excludes the potentially-large `versions` array.
• `sort_by` validated against an allow-list.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import List, Optional

from bson import ObjectId
from fastapi import APIRouter, HTTPException, Query, status

from API.database import col_products
from API.models import Product
from API.utils import (
    PROD_SORT_FIELDS,
    build_pagination_meta,
    doc_to_model,
    resolve_sort,
    serialize_doc,
)

router = APIRouter(prefix="/products", tags=["Products"])

_LIST_PROJECTION: dict = {
    "_id": 1, "name": 1, "vendor_name": 1, "vendor_id": 1,
    "sources": 1, "created_at": 1, "updated_at": 1,
    # `versions` deliberately excluded from list view — fetch via /{id}
}


# ---------------------------------------------------------------------------
# GET /API/products/
# ---------------------------------------------------------------------------

@router.get(
    "/",
    response_model=dict,
    summary="List products",
    description=(
        "Returns a paginated list of normalised software products.  \n\n"
        "**Search:** the `search` parameter uses a weighted text index "
        "across name, vendor_name, and raw_names.  \n\n"
        "The full `versions` array is **omitted** from list results for performance; "
        "use `GET /API/products/{id}` to retrieve it."
    ),
)
async def list_products(
    page: int = Query(1, ge=1, description="Page number (1-indexed)."),
    page_size: int = Query(25, ge=1, le=200, description="Results per page (max 200)."),

    vendor_name: Optional[str] = Query(None, description="Case-insensitive substring match on vendor_name."),
    product_name: Optional[str] = Query(None, description="Case-insensitive substring match on name."),
    source: Optional[str] = Query(None, description="Filter by ingest source: `csaf` or `euvd`."),

    updated_after:  Optional[datetime] = Query(None, description="Return products updated at or after this datetime."),
    updated_before: Optional[datetime] = Query(None, description="Return products updated at or before this datetime."),

    search: Optional[str] = Query(
        None,
        description="Full-text search across name, vendor_name, and raw_names (uses a weighted text index).",
    ),

    sort_by: str = Query(
        "name",
        description="Sort field. Allowed: `name`, `vendor_name`, `created_at`, `updated_at`. Prefix with `-` for descending.",
    ),
) -> dict:

    flt: dict = {}

    if search:
        flt["$text"] = {"$search": search}
    if vendor_name:
        flt["vendor_name"] = {"$regex": re.escape(vendor_name), "$options": "i"}
    if product_name:
        flt["name"] = {"$regex": re.escape(product_name), "$options": "i"}
    if source:
        flt["sources"] = source.lower()
    if updated_after or updated_before:
        cond: dict = {}
        if updated_after:
            cond["$gte"] = updated_after
        if updated_before:
            cond["$lte"] = updated_before
        flt["updated_at"] = cond

    sort_field, sort_dir = resolve_sort(sort_by, PROD_SORT_FIELDS, "name")

    text_active = "$text" in flt
    sort_doc: dict = {sort_field: sort_dir}
    if text_active:
        sort_doc["_score"] = -1  # secondary: text relevance

    skip = (page - 1) * page_size
    col  = col_products()

    pipeline: list[dict] = [{"$match": flt}]
    if text_active:
        pipeline.append({"$addFields": {"_score": {"$meta": "textScore"}}})

    data_pipe: list[dict] = [
        {"$sort": sort_doc},
        {"$skip": skip},
        {"$limit": page_size},
        {"$project": {**_LIST_PROJECTION}},
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
        if "vendor_id" in doc and isinstance(doc.get("vendor_id"), ObjectId):
            doc["vendor_id"] = str(doc["vendor_id"])
        items.append(doc)

    return {
        "data": items,
        "pagination": build_pagination_meta(total, page, page_size),
    }


# ---------------------------------------------------------------------------
# GET /API/products/{object_id}
# ---------------------------------------------------------------------------

@router.get(
    "/{object_id}",
    response_model=Product,
    summary="Get product by ObjectId",
    description=(
        "Retrieve the full product document — including the complete `versions` array — "
        "by its MongoDB `_id`."
    ),
)
async def get_product(object_id: str) -> Product:
    try:
        oid = ObjectId(object_id)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"'{object_id}' is not a valid ObjectId.",
        )
    col = col_products()
    doc = await col.find_one({"_id": oid})
    if doc is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No product found with _id '{object_id}'.",
        )
    return doc_to_model(doc, Product)
