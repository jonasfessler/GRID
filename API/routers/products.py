"""
routers/products.py — Endpoints for the GRIDd/products collection.
"""

from __future__ import annotations

from typing import List, Optional

from bson import ObjectId
from fastapi import APIRouter, HTTPException, Query, status

from API.database import col_products
from API.models import Product
from API.utils import doc_to_model, build_pagination_meta

router = APIRouter(
    prefix="/products",
    tags=["Products"],
)


# ---------------------------------------------------------------------------
# GET /API/products
# ---------------------------------------------------------------------------

@router.get(
    "/",
    response_model=dict,
    summary="List products",
    description=(
        "Returns a paginated list of normalised software products stored in GRIDd. "
        "Filter by vendor name or product name substring."
    ),
)
async def list_products(
    page: int = Query(1, ge=1, description="Page number (1-indexed)."),
    page_size: int = Query(25, ge=1, le=200, description="Number of results per page (max 200)."),
    vendor_name: Optional[str] = Query(
        None,
        description="Case-insensitive substring match on the denormalised `vendor_name` field.",
    ),
    product_name: Optional[str] = Query(
        None,
        description="Case-insensitive substring match on the normalised `name` field.",
    ),
    source: Optional[str] = Query(None, description="Filter by ingest source: 'csaf' or 'euvd'."),
) -> dict:
    flt: dict = {}

    if vendor_name:
        flt["vendor_name"] = {"$regex": vendor_name, "$options": "i"}
    if product_name:
        flt["name"] = {"$regex": product_name, "$options": "i"}
    if source:
        flt["sources"] = source.lower()

    skip  = (page - 1) * page_size
    col   = col_products()
    total = await col.count_documents(flt)

    # Return a lightweight projection for list view (no full versions array)
    projection = {"_id": 1, "name": 1, "vendor_name": 1, "vendor_id": 1, "sources": 1,
                  "created_at": 1, "updated_at": 1}
    cursor = col.find(flt, projection).sort("name", 1).skip(skip).limit(page_size)

    items: List[dict] = []
    async for doc in cursor:
        doc["_id"] = str(doc["_id"])
        if "vendor_id" in doc and doc["vendor_id"]:
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
        "Retrieve the full product document — including all known version strings — "
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
