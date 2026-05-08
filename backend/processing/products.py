"""
products.py
===========
GRIDd Product Processor: Extracts and normalizes product data from all
raw GRIDr documents (cert-bund + euvd) and upserts them into GRIDd/products.

Normalization rules are loaded from products.json at runtime.
Vendor lookup uses GRIDd/vendors (populated by vendors.py).

IMPORTANT: Run vendors.py before products.py on the first run to ensure
vendor references exist in GRIDd/vendors before products try to link to them.
Subsequent runs can run in any order — missing vendor references are created
inline with a warning.

Change Detection (Watermark)
-----------------------------
Identical mechanism to vendors.py. Watermark is stored in GRIDd/metadata
under _id "product_processor". Only GRIDr documents with
mirrored_at > last_watermark are processed.

Idempotency
-----------
Products are upserted by (normalized_vendor_name, normalized_product_name).
Re-processing a source document only updates raw_names, versions, and
sources — no duplicate product entries are created.

GRIDd/products Document Schema
--------------------------------
  {
    "_id":          ObjectId,
    "name":         "CloudStack",       # normalized product name
    "vendor_id":    ObjectId,           # FK → GRIDd/vendors._id
    "vendor_name":  "Apache",           # denormalized for query convenience
    "raw_names":    ["CloudStack", "Apache CloudStack"],
    "versions":     [
      { "version_string": "LTS <4.20.3.0", "is_range": true,  "cpe": "" },
      { "version_string": "LTS 4.20.3.0",  "is_range": false, "cpe": "cpe:..." }
    ],
    "sources":      ["csaf"],
    "created_at":   datetime,
    "updated_at":   datetime
  }

Fault Tolerance
---------------
  - Individual document errors are logged and skipped; the run continues.
  - Transient DB errors trigger configurable retries with delay.
  - Missing vendor references are created inline (upsert) with a warning.
  - The watermark is only advanced after all documents in the batch succeed.
"""

import asyncio
import json
import logging
import re
from datetime import datetime, UTC
from pathlib import Path
from typing import Any

from bson import ObjectId
from motor.motor_asyncio import AsyncIOMotorClient
from pymongo.errors import PyMongoError

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

CONFIG_DIR           = Path(__file__).parent.parent
PRODUCTS_CONFIG_PATH = CONFIG_DIR / "products.json"
VENDORS_CONFIG_PATH  = CONFIG_DIR / "vendors.json"

MONGO_URI = "mongodb://localhost:27017/"
GRIDR_DB  = "GRIDr"
GRIDD_DB  = "GRIDd"

COLL_CERT_BUND = "cert-bund"
COLL_EUVD      = "euvd"
COLL_VENDORS   = "vendors"
COLL_PRODUCTS  = "products"
COLL_META      = "metadata"

PROCESSOR_STATE_ID = "product_processor"
BATCH_SIZE         = 200
MAX_DB_RETRIES     = 3
RETRY_DELAY        = 2.0

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Config Loader
# ---------------------------------------------------------------------------

def load_configs() -> tuple[dict, dict]:
    """Loads products.json and vendors.json. Raises on missing/malformed files."""
    for path in (PRODUCTS_CONFIG_PATH, VENDORS_CONFIG_PATH):
        if not path.exists():
            raise FileNotFoundError(f"Config file not found: {path}")
    with open(PRODUCTS_CONFIG_PATH, encoding="utf-8") as f:
        products_cfg = json.load(f)
    with open(VENDORS_CONFIG_PATH, encoding="utf-8") as f:
        vendors_cfg = json.load(f)
    logger.info(
        f"Loaded products.json v{products_cfg.get('version', '?')}, "
        f"vendors.json v{vendors_cfg.get('version', '?')}"
    )
    return products_cfg, vendors_cfg

# ---------------------------------------------------------------------------
# Normalization
# ---------------------------------------------------------------------------

def normalize_vendor_name(raw: str, vendors_cfg: dict) -> str:
    """Applies vendor normalization rules (mirrors vendors.py logic)."""
    norm = vendors_cfg["normalization"]
    name = raw.strip()
    suffixes = sorted(norm["strip_suffixes"], key=len, reverse=True)
    for suffix in suffixes:
        if name.endswith(suffix):
            name = name[: -len(suffix)].strip()
            break
    if norm["formatting"].get("case_handling") == "proper_case":
        name = name.title()
    return name.strip() or raw.strip()


def normalize_product_name(
    raw: str,
    normalized_vendor: str,
    products_cfg: dict,
) -> str:
    """
    Applies product normalization rules from products.json.

    Steps:
      1. Trim whitespace.
      2. Strip vendor prefix if product name starts with vendor name.
      3. Remove generic version-noise patterns (e.g. ' version ', ' v.').
      4. Apply title case.
    """
    name = raw.strip()
    norm = products_cfg["normalization"]

    # Strip vendor prefix (e.g. "Apache CloudStack" → "CloudStack")
    if norm.get("strip_vendor_prefix", {}).get("enabled"):
        prefix = normalized_vendor + " "
        if name.lower().startswith(prefix.lower()):
            name = name[len(prefix):].strip()

    # Remove noise patterns
    for pattern in norm.get("clean_patterns", []):
        name = name.replace(pattern, " ")

    # Collapse multiple spaces and apply title case
    name = re.sub(r"\s+", " ", name).strip().title()

    return name or raw.strip()


def parse_version_string(raw: str) -> dict[str, Any]:
    """
    Parses a raw version string into a structured dict.

    Examples:
      "LTS <4.20.3.0"  → { version_string: "LTS <4.20.3.0", is_range: True,  cpe: "" }
      "6.6.138"        → { version_string: "6.6.138",        is_range: False, cpe: "" }
      "0 <3.1.2"       → { version_string: "0 <3.1.2",       is_range: True,  cpe: "" }
    """
    is_range = bool(re.search(r"[<>]=?|<<", raw))
    return {"version_string": raw.strip(), "is_range": is_range, "cpe": ""}

# ---------------------------------------------------------------------------
# Extraction: CSAF
# ---------------------------------------------------------------------------

def extract_products_from_csaf(doc: dict) -> list[dict[str, Any]]:
    """
    Walks the CSAF product_tree branch hierarchy:
      vendor (category='vendor')
        └── product_name (category='product_name')
              └── version branches (category='product_version' | 'product_version_range')

    Returns a list of product dicts:
      { raw_vendor, raw_product, versions: [{version_string, is_range, cpe}] }
    """
    results: list[dict] = []
    branches = doc.get("product_tree", {}).get("branches", [])

    for vendor_branch in branches:
        if vendor_branch.get("category") != "vendor":
            continue
        raw_vendor = (vendor_branch.get("name") or "").strip()
        if not raw_vendor:
            continue

        for product_branch in vendor_branch.get("branches", []):
            if product_branch.get("category") != "product_name":
                continue
            raw_product = (product_branch.get("name") or "").strip()
            if not raw_product:
                continue

            versions: list[dict] = []
            for ver_branch in product_branch.get("branches", []):
                cat = ver_branch.get("category", "")
                if cat not in ("product_version", "product_version_range"):
                    continue
                ver_str = (ver_branch.get("name") or "").strip()
                parsed  = parse_version_string(ver_str)

                # Extract CPE if available
                product_obj = ver_branch.get("product") or {}
                helper      = product_obj.get("product_identification_helper") or {}
                parsed["cpe"] = helper.get("cpe", "")

                versions.append(parsed)

            results.append({
                "raw_vendor":  raw_vendor,
                "raw_product": raw_product,
                "versions":    versions,
            })

    return results

# ---------------------------------------------------------------------------
# Extraction: EUVD
# ---------------------------------------------------------------------------

def extract_products_from_euvd(doc: dict) -> list[dict[str, Any]]:
    """
    Extracts products from EUVD structure.

    Links vendors to products via the shared 'id' field:
      enisaIdVendor[].id  ↔  enisaIdProduct[].id

    Returns a list of product dicts:
      { raw_vendor, raw_product, versions: [{version_string, is_range, cpe}] }
    """
    # Build vendor lookup: id → vendor.name
    vendor_map: dict[str, str] = {}
    for entry in doc.get("enisaIdVendor", []):
        vid   = entry.get("id", "")
        vname = ((entry.get("vendor") or {}).get("name") or "").strip()
        if vid and vname:
            vendor_map[vid] = vname

    results: list[dict] = []
    for entry in doc.get("enisaIdProduct", []):
        pid          = entry.get("id", "")
        raw_product  = ((entry.get("product") or {}).get("name") or "").strip()
        version_str  = (entry.get("product_version") or "").strip()

        if not raw_product:
            continue

        # Link to vendor by matching id; fall back to first vendor if no match
        raw_vendor = (
            vendor_map.get(pid)
            or (next(iter(vendor_map.values()), None))
            or ""
        )

        versions = [parse_version_string(version_str)] if version_str else []

        results.append({
            "raw_vendor":  raw_vendor,
            "raw_product": raw_product,
            "versions":    versions,
        })

    return results

# ---------------------------------------------------------------------------
# DB Helpers
# ---------------------------------------------------------------------------

async def _retry(coro_fn, retries: int = MAX_DB_RETRIES, delay: float = RETRY_DELAY):
    """Executes async callable with retry on PyMongoError."""
    last_exc: Exception | None = None
    for attempt in range(retries + 1):
        try:
            return await coro_fn()
        except PyMongoError as exc:
            last_exc = exc
            if attempt < retries:
                logger.warning(f"  [DB ERROR] {exc} — retry {attempt + 1}/{retries} in {delay}s...")
                await asyncio.sleep(delay)
    raise last_exc


async def load_watermark(db_gridd) -> datetime:
    """Returns last successful run watermark, or epoch start if none."""
    doc = await db_gridd[COLL_META].find_one({"_id": PROCESSOR_STATE_ID})
    if doc and doc.get("last_watermark"):
        wm = doc["last_watermark"]
        if wm.tzinfo is None:
            wm = wm.replace(tzinfo=UTC)
        return wm
    return datetime.min.replace(tzinfo=UTC)


async def save_watermark(db_gridd, watermark: datetime) -> None:
    """Persists new watermark to GRIDd/metadata."""
    await db_gridd[COLL_META].update_one(
        {"_id": PROCESSOR_STATE_ID},
        {"$set": {"last_watermark": watermark, "updated_at": datetime.now(UTC)}},
        upsert=True,
    )
    logger.info(f"Watermark advanced to {watermark.isoformat()}")


async def get_or_create_vendor(
    db_gridd,
    raw_vendor: str,
    normalized_vendor: str,
    source: str,
) -> ObjectId | None:
    """
    Looks up a vendor in GRIDd/vendors by normalized name.
    Creates it inline (with a warning) if it doesn't exist yet.
    Returns the vendor's _id, or None on error.
    """
    if not normalized_vendor:
        return None

    now = datetime.now(UTC)

    result = await _retry(lambda: db_gridd[COLL_VENDORS].find_one_and_update(
        {"name": normalized_vendor},
        {
            "$set":         {"name": normalized_vendor, "updated_at": now},
            "$setOnInsert": {"created_at": now},
            "$addToSet":    {"raw_names": raw_vendor, "sources": source},
        },
        upsert=True,
        return_document=True,
    ))

    if not result:
        logger.warning(f"  [WARN] Could not get/create vendor '{normalized_vendor}'")
        return None

    if result.get("created_at") == now:
        logger.warning(
            f"  [WARN] Vendor '{normalized_vendor}' not found in GRIDd/vendors — "
            f"created inline. Run vendors.py first to avoid this."
        )

    return result["_id"]


async def ensure_indexes(db_gridd) -> None:
    """Creates indexes on GRIDd/products (idempotent)."""
    await db_gridd[COLL_PRODUCTS].create_index(
        [("vendor_name", 1), ("name", 1)], unique=True
    )
    await db_gridd[COLL_PRODUCTS].create_index("vendor_id")
    logger.info("Indexes on GRIDd/products verified.")

# ---------------------------------------------------------------------------
# Upsert
# ---------------------------------------------------------------------------

async def upsert_product(
    db_gridd,
    raw_product:       str,
    normalized_product: str,
    vendor_id:         ObjectId | None,
    normalized_vendor: str,
    versions:          list[dict],
    source:            str,
) -> None:
    """
    Upserts a product into GRIDd/products by (vendor_name, name).
    Accumulates raw_names, versions (by version_string), and sources.
    """
    now = datetime.now(UTC)

    # Merge versions: add new version strings, don't duplicate existing ones
    version_updates = [
        {"$addToSet": {"versions": ver}}
        for ver in versions
    ]

    await _retry(lambda: db_gridd[COLL_PRODUCTS].update_one(
        {"vendor_name": normalized_vendor, "name": normalized_product},
        {
            "$set":         {
                "name":        normalized_product,
                "vendor_name": normalized_vendor,
                "vendor_id":   vendor_id,
                "updated_at":  now,
            },
            "$setOnInsert": {"created_at": now},
            "$addToSet":    {
                "raw_names": raw_product,
                "sources":   source,
                "versions":  {"$each": versions},
            },
        },
        upsert=True,
    ))

# ---------------------------------------------------------------------------
# Batch Processor
# ---------------------------------------------------------------------------

async def process_collection(
    db_gridr,
    db_gridd,
    collection:   str,
    source:       str,
    extract_fn,
    products_cfg: dict,
    vendors_cfg:  dict,
    watermark:    datetime,
) -> tuple[int, int, datetime | None]:
    """
    Queries a GRIDr collection for documents newer than watermark,
    extracts products from each, and upserts them into GRIDd/products.

    Returns (docs_processed, products_upserted, max_mirrored_at).
    """
    query  = {"mirrored_at": {"$gt": watermark}}
    cursor = db_gridr[collection].find(
        query,
        {"mirrored_at": 1, "product_tree": 1, "enisaIdVendor": 1, "enisaIdProduct": 1},
    ).batch_size(BATCH_SIZE)

    docs_processed    = 0
    products_upserted = 0
    max_mirrored_at: datetime | None = None

    async for doc in cursor:
        try:
            mirrored = doc.get("mirrored_at")
            if mirrored and mirrored.tzinfo is None:
                mirrored = mirrored.replace(tzinfo=UTC)
            if mirrored and (max_mirrored_at is None or mirrored > max_mirrored_at):
                max_mirrored_at = mirrored

            product_entries = extract_fn(doc)

            for entry in product_entries:
                raw_vendor  = entry["raw_vendor"]
                raw_product = entry["raw_product"]
                versions    = entry["versions"]

                norm_vendor  = normalize_vendor_name(raw_vendor, vendors_cfg)
                norm_product = normalize_product_name(raw_product, norm_vendor, products_cfg)

                if not norm_product:
                    continue

                vendor_id = await get_or_create_vendor(
                    db_gridd, raw_vendor, norm_vendor, source
                )

                await upsert_product(
                    db_gridd,
                    raw_product=raw_product,
                    normalized_product=norm_product,
                    vendor_id=vendor_id,
                    normalized_vendor=norm_vendor,
                    versions=versions,
                    source=source,
                )
                products_upserted += 1
                logger.debug(
                    f"  [PRODUCT] {raw_product!r} → {norm_product!r} "
                    f"(vendor: {norm_vendor!r}, {source})"
                )

            docs_processed += 1

        except Exception as exc:
            logger.error(f"  [ERROR] Failed to process doc {doc.get('_id')}: {exc}")

    return docs_processed, products_upserted, max_mirrored_at

# ---------------------------------------------------------------------------
# Entry Point
# ---------------------------------------------------------------------------

async def run() -> None:
    """
    Main coroutine.

    Steps
    -----
    1. Load products.json and vendors.json configs.
    2. Connect to GRIDr and GRIDd.
    3. Load the current watermark from GRIDd/metadata.
    4. Process cert-bund collection (CSAF branch hierarchy extraction).
    5. Process euvd collection (EUVD enisaIdProduct extraction).
    6. Advance watermark to highest mirrored_at value in this batch.
    """
    products_cfg, vendors_cfg = load_configs()

    mongo_client = AsyncIOMotorClient(MONGO_URI)
    db_gridr     = mongo_client[GRIDR_DB]
    db_gridd     = mongo_client[GRIDD_DB]

    try:
        await ensure_indexes(db_gridd)

        watermark = await load_watermark(db_gridd)
        logger.info("=" * 60)
        logger.info(f"PRODUCT PROCESSOR STARTED — watermark: {watermark.isoformat()}")
        logger.info("=" * 60)

        total_docs     = 0
        total_products = 0
        new_watermark: datetime | None = None

        # --- CSAF (cert-bund) ---
        docs, products, wm = await process_collection(
            db_gridr, db_gridd,
            collection=COLL_CERT_BUND,
            source="csaf",
            extract_fn=extract_products_from_csaf,
            products_cfg=products_cfg,
            vendors_cfg=vendors_cfg,
            watermark=watermark,
        )
        logger.info(f"  cert-bund: {docs} docs processed, {products} product entries upserted.")
        total_docs     += docs
        total_products += products
        if wm and (new_watermark is None or wm > new_watermark):
            new_watermark = wm

        # --- EUVD ---
        docs, products, wm = await process_collection(
            db_gridr, db_gridd,
            collection=COLL_EUVD,
            source="euvd",
            extract_fn=extract_products_from_euvd,
            products_cfg=products_cfg,
            vendors_cfg=vendors_cfg,
            watermark=watermark,
        )
        logger.info(f"  euvd: {docs} docs processed, {products} product entries upserted.")
        total_docs     += docs
        total_products += products
        if wm and (new_watermark is None or wm > new_watermark):
            new_watermark = wm

        # --- Advance watermark ---
        if new_watermark:
            await save_watermark(db_gridd, new_watermark)
        else:
            logger.info("  No new documents found — watermark unchanged.")

        logger.info("=" * 60)
        logger.info(
            f"PRODUCT PROCESSOR COMPLETE — "
            f"{total_docs} docs processed, "
            f"{total_products} product entries upserted."
        )

    except FileNotFoundError as exc:
        logger.error(f"CRITICAL: Config file missing — {exc}")
    except PyMongoError as exc:
        logger.error(f"CRITICAL: Database error — {exc}")
    except Exception as exc:
        logger.error(f"CRITICAL: Unexpected error — {exc}")
        raise
    finally:
        mongo_client.close()


if __name__ == "__main__":
    asyncio.run(run())
