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

Performance
-----------
  - Both collections (cert-bund, euvd) are processed concurrently.
  - Product entries within a document are upserted concurrently via asyncio
    semaphore-bounded gather (CONCURRENCY workers at a time).
  - Vendors are cached in-memory to avoid repeated DB lookups.
  - Bulk writes (UpdateOne ops) are flushed in UPSERT_BUFFER_SIZE batches.
"""

import asyncio
import json
import logging
import re
import time
from datetime import datetime, UTC
from pathlib import Path
from typing import Any

from bson import ObjectId
from motor.motor_asyncio import AsyncIOMotorClient
from pymongo import UpdateOne
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

PROCESSOR_STATE_ID  = "product_processor"
BATCH_SIZE          = 500           # cursor batch size (was 200)
UPSERT_BUFFER_SIZE  = 500           # bulk-write flush threshold
CONCURRENCY         = 20            # max concurrent entry-processing tasks
MAX_DB_RETRIES      = 3
RETRY_DELAY         = 2.0

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


async def ensure_indexes(db_gridd) -> None:
    """Creates indexes on GRIDd/products (idempotent)."""
    await db_gridd[COLL_PRODUCTS].create_index(
        [("vendor_name", 1), ("name", 1)], unique=True
    )
    await db_gridd[COLL_PRODUCTS].create_index("vendor_id")
    logger.info("Indexes on GRIDd/products verified.")

# ---------------------------------------------------------------------------
# Vendor Cache
# ---------------------------------------------------------------------------

class VendorCache:
    """
    In-memory cache for vendor lookups/creation within a single run.
    Avoids repeated DB round-trips for the same normalized vendor name.
    Thread-safe via asyncio.Lock per vendor name.
    """

    def __init__(self) -> None:
        self._cache: dict[str, ObjectId | None] = {}
        self._locks: dict[str, asyncio.Lock] = {}
        self._global_lock = asyncio.Lock()

    async def get_or_create(
        self,
        db_gridd,
        raw_vendor: str,
        normalized_vendor: str,
        source: str,
    ) -> ObjectId | None:
        """Returns vendor _id (from cache or DB upsert). None on error."""
        if not normalized_vendor:
            return None

        # Fast path — already cached
        if normalized_vendor in self._cache:
            return self._cache[normalized_vendor]

        # Get or create a per-vendor lock
        async with self._global_lock:
            if normalized_vendor not in self._locks:
                self._locks[normalized_vendor] = asyncio.Lock()
            lock = self._locks[normalized_vendor]

        async with lock:
            # Double-check after acquiring the lock
            if normalized_vendor in self._cache:
                return self._cache[normalized_vendor]

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
                self._cache[normalized_vendor] = None
                return None

            if result.get("created_at") == now:
                logger.warning(
                    f"  [WARN] Vendor '{normalized_vendor}' not found in GRIDd/vendors — "
                    f"created inline. Run vendors.py first to avoid this."
                )

            self._cache[normalized_vendor] = result["_id"]
            return result["_id"]

# ---------------------------------------------------------------------------
# Bulk Upsert Buffer
# ---------------------------------------------------------------------------

class BulkUpsertBuffer:
    """
    Accumulates UpdateOne operations and flushes them as bulk_write batches.
    Much faster than individual update_one calls for high-volume upserts.
    """

    def __init__(self, collection, buffer_size: int = UPSERT_BUFFER_SIZE) -> None:
        self._collection = collection
        self._buffer_size = buffer_size
        self._ops: list[UpdateOne] = []
        self._flushed = 0

    def add(self, op: UpdateOne) -> None:
        self._ops.append(op)

    @property
    def pending(self) -> int:
        return len(self._ops)

    @property
    def total_flushed(self) -> int:
        return self._flushed

    async def maybe_flush(self) -> int:
        """Flushes if buffer is at or above threshold. Returns ops flushed."""
        if len(self._ops) >= self._buffer_size:
            return await self.flush()
        return 0

    async def flush(self) -> int:
        """Flushes all pending operations. Returns number flushed."""
        if not self._ops:
            return 0
        ops = self._ops
        self._ops = []
        count = len(ops)
        await _retry(lambda: self._collection.bulk_write(ops, ordered=False))
        self._flushed += count
        return count

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
    vendor_cache: VendorCache,
) -> tuple[int, int, datetime | None]:
    """
    Queries a GRIDr collection for documents newer than watermark,
    extracts products from each, and upserts them into GRIDd/products.

    Product entries within each document are processed concurrently
    (bounded by CONCURRENCY semaphore) and written via bulk_write.

    Returns (docs_processed, products_upserted, max_mirrored_at).
    """
    # Count total documents for progress reporting
    total_count = await db_gridr[collection].count_documents(
        {"mirrored_at": {"$gt": watermark}}
    )
    logger.info(f"[{source.upper()}] Found {total_count} documents to process.")

    if total_count == 0:
        return 0, 0, None

    query  = {"mirrored_at": {"$gt": watermark}}
    cursor = db_gridr[collection].find(
        query,
        {"mirrored_at": 1, "product_tree": 1, "enisaIdVendor": 1, "enisaIdProduct": 1,
         "document": 1},
    ).batch_size(BATCH_SIZE)

    docs_processed    = 0
    products_upserted = 0
    max_mirrored_at: datetime | None = None

    semaphore = asyncio.Semaphore(CONCURRENCY)
    bulk = BulkUpsertBuffer(db_gridd[COLL_PRODUCTS])

    t_start = time.perf_counter()

    async for doc in cursor:
        try:
            mirrored = doc.get("mirrored_at")
            if mirrored and mirrored.tzinfo is None:
                mirrored = mirrored.replace(tzinfo=UTC)
            if mirrored and (max_mirrored_at is None or mirrored > max_mirrored_at):
                max_mirrored_at = mirrored

            product_entries = extract_fn(doc)

            # Identify this document for logging
            doc_id = (
                doc.get("document", {}).get("tracking", {}).get("id")
                or doc.get("id")
                or str(doc.get("_id", "?"))
            )

            if not product_entries:
                docs_processed += 1
                logger.info(
                    f"  [{source.upper()}] [{docs_processed}/{total_count}] "
                    f"{doc_id} — 0 products (skipped)"
                )
                continue

            # --- Process all entries concurrently with semaphore bound ---
            async def process_entry(entry: dict) -> UpdateOne | None:
                async with semaphore:
                    raw_vendor  = entry["raw_vendor"]
                    raw_product = entry["raw_product"]
                    versions    = entry["versions"]

                    norm_vendor  = normalize_vendor_name(raw_vendor, vendors_cfg)
                    norm_product = normalize_product_name(raw_product, norm_vendor, products_cfg)

                    if not norm_product:
                        return None

                    vendor_id = await vendor_cache.get_or_create(
                        db_gridd, raw_vendor, norm_vendor, source
                    )

                    now = datetime.now(UTC)
                    op = UpdateOne(
                        {"vendor_name": norm_vendor, "name": norm_product},
                        {
                            "$set":         {
                                "name":        norm_product,
                                "vendor_name": norm_vendor,
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
                    )

                    logger.debug(
                        f"    [PRODUCT] {raw_product!r} → {norm_product!r} "
                        f"(vendor: {norm_vendor!r}, {source})"
                    )
                    return op

            # Gather all entry tasks concurrently
            results = await asyncio.gather(
                *(process_entry(e) for e in product_entries),
                return_exceptions=True,
            )

            entry_count = 0
            entry_errors = 0
            for r in results:
                if isinstance(r, Exception):
                    entry_errors += 1
                    logger.error(f"    [ERROR] Entry processing failed: {r}")
                elif r is not None:
                    bulk.add(r)
                    entry_count += 1

            # Flush if buffer is full
            flushed = await bulk.maybe_flush()
            if flushed:
                logger.info(f"    [BULK FLUSH] Wrote {flushed} product upserts to DB")

            products_upserted += entry_count
            docs_processed    += 1

            # Per-document progress log (like join.py)
            elapsed = time.perf_counter() - t_start
            rate    = docs_processed / elapsed if elapsed > 0 else 0
            error_note = f", {entry_errors} errors" if entry_errors else ""
            logger.info(
                f"  [{source.upper()}] [{docs_processed}/{total_count}] "
                f"{doc_id} — {entry_count} products{error_note} "
                f"({rate:.1f} docs/s)"
            )

        except Exception as exc:
            logger.error(f"  [ERROR] Failed to process doc {doc.get('_id')}: {exc}")

    # Final flush of remaining buffered ops
    remaining = await bulk.flush()
    if remaining:
        logger.info(f"  [{source.upper()}] [BULK FLUSH] Final write: {remaining} product upserts")

    elapsed = time.perf_counter() - t_start
    logger.info(
        f"  [{source.upper()}] Done: {docs_processed} docs, "
        f"{products_upserted} products in {elapsed:.1f}s "
        f"(buffer flushed {bulk.total_flushed} total ops)"
    )

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
    4. Process cert-bund and euvd collections concurrently.
    5. Advance watermark to highest mirrored_at value in this batch.
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

        # Shared vendor cache across both collections
        vendor_cache = VendorCache()

        t_start = time.perf_counter()

        # --- Process both collections concurrently ---
        csaf_task = asyncio.create_task(
            process_collection(
                db_gridr, db_gridd,
                collection=COLL_CERT_BUND,
                source="csaf",
                extract_fn=extract_products_from_csaf,
                products_cfg=products_cfg,
                vendors_cfg=vendors_cfg,
                watermark=watermark,
                vendor_cache=vendor_cache,
            )
        )
        euvd_task = asyncio.create_task(
            process_collection(
                db_gridr, db_gridd,
                collection=COLL_EUVD,
                source="euvd",
                extract_fn=extract_products_from_euvd,
                products_cfg=products_cfg,
                vendors_cfg=vendors_cfg,
                watermark=watermark,
                vendor_cache=vendor_cache,
            )
        )

        (csaf_docs, csaf_products, csaf_wm), (euvd_docs, euvd_products, euvd_wm) = (
            await asyncio.gather(csaf_task, euvd_task)
        )

        total_docs     = csaf_docs + euvd_docs
        total_products = csaf_products + euvd_products

        logger.info(f"  cert-bund: {csaf_docs} docs processed, {csaf_products} product entries upserted.")
        logger.info(f"  euvd: {euvd_docs} docs processed, {euvd_products} product entries upserted.")

        # --- Advance watermark ---
        new_watermark: datetime | None = None
        for wm in (csaf_wm, euvd_wm):
            if wm and (new_watermark is None or wm > new_watermark):
                new_watermark = wm

        if new_watermark:
            await save_watermark(db_gridd, new_watermark)
        else:
            logger.info("  No new documents found — watermark unchanged.")

        elapsed = time.perf_counter() - t_start
        logger.info("=" * 60)
        logger.info(
            f"PRODUCT PROCESSOR COMPLETE — "
            f"{total_docs} docs processed, "
            f"{total_products} product entries upserted "
            f"in {elapsed:.1f}s."
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
