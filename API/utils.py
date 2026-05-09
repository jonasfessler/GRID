"""
utils.py — Shared helper utilities for the GRID API.
"""

from __future__ import annotations

import math
from typing import Any, Type, TypeVar

from bson import ObjectId

T = TypeVar("T")


def doc_to_model(doc: dict, model_cls: Type[T]) -> T:
    """
    Convert a raw MongoDB document to a Pydantic model.

    Handles the common ObjectId → str conversion for `_id` and nested
    ObjectId fields (vendor_id, product_id inside infrastructure.links).
    """
    # Shallow copy to avoid mutating the cursor document
    doc = dict(doc)

    # Top-level _id
    if "_id" in doc and isinstance(doc["_id"], ObjectId):
        doc["_id"] = str(doc["_id"])

    # GRIDd/products: vendor_id
    if "vendor_id" in doc and isinstance(doc["vendor_id"], ObjectId):
        doc["vendor_id"] = str(doc["vendor_id"])

    # GRIDd/advisories: infrastructure.links[].vendor_id / product_id
    infra = doc.get("infrastructure")
    if isinstance(infra, dict):
        for link in infra.get("links", []):
            if isinstance(link.get("vendor_id"), ObjectId):
                link["vendor_id"] = str(link["vendor_id"])
            if isinstance(link.get("product_id"), ObjectId):
                link["product_id"] = str(link["product_id"])

    return model_cls.model_validate(doc)


def build_pagination_meta(total: int, page: int, page_size: int) -> dict:
    """Return a standardised pagination metadata block."""
    total_pages = math.ceil(total / page_size) if page_size else 0
    return {
        "total":       total,
        "page":        page,
        "page_size":   page_size,
        "total_pages": total_pages,
        "has_next":    page < total_pages,
        "has_prev":    page > 1,
    }
