"""
utils.py — Shared helper utilities for the GRID API.
"""

from __future__ import annotations

import math
import time
from typing import Any, Callable, Coroutine, Type, TypeVar

from bson import ObjectId

T = TypeVar("T")


# ---------------------------------------------------------------------------
# Pydantic / MongoDB helpers
# ---------------------------------------------------------------------------

def doc_to_model(doc: dict, model_cls: Type[T]) -> T:
    """
    Convert a raw MongoDB document to a Pydantic model.

    Handles ObjectId → str conversion for _id and any nested ObjectId
    fields (vendor_id, product_id inside infrastructure.links).
    """
    doc = dict(doc)

    if "_id" in doc and isinstance(doc["_id"], ObjectId):
        doc["_id"] = str(doc["_id"])

    if "vendor_id" in doc and isinstance(doc["vendor_id"], ObjectId):
        doc["vendor_id"] = str(doc["vendor_id"])

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


def serialize_doc(doc: dict) -> dict:
    """Stringify any ObjectId fields in a raw MongoDB document dict."""
    doc["_id"] = str(doc["_id"])
    if "vendor_id" in doc and isinstance(doc.get("vendor_id"), ObjectId):
        doc["vendor_id"] = str(doc["vendor_id"])
    return doc


# ---------------------------------------------------------------------------
# In-memory TTL cache
# ---------------------------------------------------------------------------

class TTLCache:
    """
    Tiny async-safe in-memory cache with a per-key time-to-live.

    Usage:
        cache = TTLCache(ttl=60)

        async def expensive():
            return await cache.get_or_set("key", some_async_fn)
    """

    def __init__(self, ttl: float = 60.0) -> None:
        self._ttl = ttl
        self._store: dict[str, tuple[Any, float]] = {}  # key → (value, expires_at)

    def _is_valid(self, key: str) -> bool:
        entry = self._store.get(key)
        return entry is not None and time.monotonic() < entry[1]

    def get(self, key: str) -> Any:
        if self._is_valid(key):
            return self._store[key][0]
        return None

    def set(self, key: str, value: Any) -> None:
        self._store[key] = (value, time.monotonic() + self._ttl)

    def invalidate(self, key: str) -> None:
        self._store.pop(key, None)

    async def get_or_set(
        self,
        key: str,
        fn: Callable[[], Coroutine[Any, Any, Any]],
    ) -> Any:
        cached = self.get(key)
        if cached is not None:
            return cached
        result = await fn()
        self.set(key, result)
        return result


# ---------------------------------------------------------------------------
# Sort-field allow-lists  (prevent arbitrary field traversal)
# ---------------------------------------------------------------------------

#: Allowed sort fields for /API/advisories/
ADV_SORT_FIELDS: dict[str, str] = {
    "timeline.published_at":       "timeline.published_at",
    "timeline.modified_at":        "timeline.modified_at",
    "metrics.cvss_v3.base_score":  "metrics.cvss_v3.base_score",
    "metrics.epss":                "metrics.epss",
    "cve_id":                      "cve_id",
    "title":                       "title",
}
_ADV_DEFAULT_SORT = "timeline.published_at"

#: Allowed sort fields for /API/products/
PROD_SORT_FIELDS: dict[str, str] = {
    "name":        "name",
    "vendor_name": "vendor_name",
    "created_at":  "created_at",
    "updated_at":  "updated_at",
}
_PROD_DEFAULT_SORT = "name"

#: Allowed sort fields for /API/vendors/
VEND_SORT_FIELDS: dict[str, str] = {
    "name":       "name",
    "created_at": "created_at",
    "updated_at": "updated_at",
}
_VEND_DEFAULT_SORT = "name"


def resolve_sort(raw: str, allowed: dict[str, str], default: str) -> tuple[str, int]:
    """
    Parse a `sort_by` query parameter into (mongo_field, direction).

    Accepts an optional leading '-' for descending order.
    Falls back to *default* if the field is not in the allow-list.
    """
    descending = raw.startswith("-")
    field_key  = raw.lstrip("-")
    field      = allowed.get(field_key, default)
    direction  = -1 if descending else 1
    return field, direction
