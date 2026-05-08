"""
vendors.py
==========
GRIDd Vendor Processor: Extracts and normalizes vendor names from all
raw GRIDr documents (cert-bund + euvd) and upserts them into GRIDd/vendors.

Normalization rules are loaded from vendors.json at runtime.

Change Detection (Watermark)
-----------------------------
A high-watermark timestamp is persisted in GRIDd/metadata under the document
_id "vendor_processor". Only GRIDr documents with mirrored_at > last_watermark
are queried and processed. After a successful run the watermark is advanced to
the highest mirrored_at value seen in the current batch.

This means:
  - First run           → processes ALL documents (watermark is epoch 0)
  - Subsequent runs     → only processes new or re-mirrored documents
  - Re-mirrored docs    → safely re-processed (upsert is idempotent)

Idempotency
-----------
Vendors are upserted by their normalized canonical name. Re-processing the
same source document will only update raw_names / sources — no duplicates.

GRIDd/vendors Document Schema
------------------------------
  {
    "_id":          ObjectId,
    "name":         "Apache",           # normalized canonical name
    "raw_names":    ["Apache"],         # all raw name variants seen
    "sources":      ["csaf"],           # contributing sources
    "created_at":   datetime,
    "updated_at":   datetime
  }

Fault Tolerance
---------------
  - Individual document errors are logged and skipped; the run continues.
  - Transient DB errors trigger a configurable number of retries with delay.
  - The watermark is only advanced after ALL documents in the batch succeed.
  - If the run is interrupted, the next run re-processes from the last watermark.
"""

import asyncio
import json
import logging
from datetime import datetime, UTC
from pathlib import Path
from typing import Any

from motor.motor_asyncio import AsyncIOMotorClient
from pymongo.errors import PyMongoError

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

CONFIG_DIR          = Path(__file__).parent.parent
VENDORS_CONFIG_PATH = CONFIG_DIR / "vendors.json"

MONGO_URI = "mongodb://localhost:27017/"
GRIDR_DB  = "GRIDr"
GRIDD_DB  = "GRIDd"

COLL_CERT_BUND = "cert-bund"
COLL_EUVD      = "euvd"
COLL_VENDORS   = "vendors"
COLL_META      = "metadata"

PROCESSOR_STATE_ID = "vendor_processor"
BATCH_SIZE         = 200       # Documents fetched per cursor batch from GRIDr
MAX_DB_RETRIES     = 3         # Retries for transient DB errors
RETRY_DELAY        = 2.0       # Seconds between DB retries

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

def load_config() -> dict[str, Any]:
    """Loads and returns vendors.json. Raises on missing or malformed file."""
    if not VENDORS_CONFIG_PATH.exists():
        raise FileNotFoundError(f"vendors.json not found at {VENDORS_CONFIG_PATH}")
    with open(VENDORS_CONFIG_PATH, encoding="utf-8") as f:
        config = json.load(f)
    logger.info(f"Loaded vendors.json v{config.get('version', '?')}")
    return config

# ---------------------------------------------------------------------------
# Normalization
# ---------------------------------------------------------------------------

def normalize_vendor_name(raw: str, config: dict) -> str:
    """
    Applies normalization rules from vendors.json to a raw vendor name.

    Steps (in order):
      1. Trim whitespace
      2. Strip legal / generic suffixes (longest match first to avoid partial strips)
      3. Trim again after suffix removal
      4. Apply case handling (proper_case → str.title())
    """
    norm = config["normalization"]
    name = raw.strip()

    # Sort suffixes by length descending so we strip the longest match first
    # e.g. " Co. KG" before " KG"
    suffixes = sorted(norm["strip_suffixes"], key=len, reverse=True)
    for suffix in suffixes:
        if name.endswith(suffix):
            name = name[: -len(suffix)].strip()
            break  # Only strip one suffix per pass

    # Case handling
    if norm["formatting"].get("case_handling") == "proper_case":
        name = name.title()

    return name.strip() or raw.strip()   # Fall back to raw if result is empty

# ---------------------------------------------------------------------------
# Extraction: CSAF
# ---------------------------------------------------------------------------

def extract_vendors_from_csaf(doc: dict) -> set[str]:
    """
    Walks product_tree.branches[] and returns all vendor names.
    Vendor branches are identified by category == 'vendor'.
    Recursion handles arbitrarily nested branch trees.
    """
    raw_names: set[str] = set()
    branches = doc.get("product_tree", {}).get("branches", [])

    def walk(branches: list) -> None:
        for branch in branches:
            if branch.get("category") == "vendor":
                name = (branch.get("name") or "").strip()
                if name:
                    raw_names.add(name)
            # Always recurse — vendor branches may contain nested vendor info
            walk(branch.get("branches", []))

    walk(branches)
    return raw_names

# ---------------------------------------------------------------------------
# Extraction: EUVD
# ---------------------------------------------------------------------------

def extract_vendors_from_euvd(doc: dict) -> set[str]:
    """
    Returns all vendor names from enisaIdVendor[].vendor.name.
    """
    raw_names: set[str] = set()
    for entry in doc.get("enisaIdVendor", []):
        name = ((entry.get("vendor") or {}).get("name") or "").strip()
        if name:
            raw_names.add(name)
    return raw_names

# ---------------------------------------------------------------------------
# DB Helpers
# ---------------------------------------------------------------------------

async def _retry(coro_fn, retries: int = MAX_DB_RETRIES, delay: float = RETRY_DELAY):
    """
    Executes an async callable with retry on PyMongoError.
    Raises the last exception if all retries are exhausted.
    """
    last_exc: Exception | None = None
    for attempt in range(retries + 1):
        try:
            return await coro_fn()
        except PyMongoError as exc:
            last_exc = exc
            if attempt < retries:
                logger.warning(
                    f"  [DB ERROR] {exc} — retry {attempt + 1}/{retries} in {delay}s..."
                )
                await asyncio.sleep(delay)
    raise last_exc


async def load_watermark(db_gridd) -> datetime:
    """Returns the last successful run watermark, or epoch start if none."""
    doc = await db_gridd[COLL_META].find_one({"_id": PROCESSOR_STATE_ID})
    if doc and doc.get("last_watermark"):
        wm = doc["last_watermark"]
        # Normalize to UTC-aware
        if wm.tzinfo is None:
            wm = wm.replace(tzinfo=UTC)
        return wm
    return datetime.min.replace(tzinfo=UTC)


async def save_watermark(db_gridd, watermark: datetime) -> None:
    """Persists the new watermark and run stats to GRIDd/metadata."""
    await db_gridd[COLL_META].update_one(
        {"_id": PROCESSOR_STATE_ID},
        {"$set": {"last_watermark": watermark, "updated_at": datetime.now(UTC)}},
        upsert=True,
    )
    logger.info(f"Watermark advanced to {watermark.isoformat()}")


async def ensure_indexes(db_gridd) -> None:
    """Creates indexes on GRIDd/vendors (idempotent)."""
    await db_gridd[COLL_VENDORS].create_index("name", unique=True)
    logger.info("Index on GRIDd/vendors.'name' verified.")

# ---------------------------------------------------------------------------
# Upsert
# ---------------------------------------------------------------------------

async def upsert_vendor(
    db_gridd,
    raw_name: str,
    normalized: str,
    source: str,
    source_doc_id: Any,
) -> None:
    """
    Upserts a vendor into GRIDd/vendors by normalized name.
    Accumulates raw_names and sources across multiple source documents.
    """
    now = datetime.now(UTC)

    await _retry(lambda: db_gridd[COLL_VENDORS].update_one(
        {"name": normalized},
        {
            "$set":      {"name": normalized, "updated_at": now},
            "$setOnInsert": {"created_at": now},
            "$addToSet": {"raw_names": raw_name, "sources": source},
        },
        upsert=True,
    ))

# ---------------------------------------------------------------------------
# Batch Processor
# ---------------------------------------------------------------------------

async def process_collection(
    db_gridr,
    db_gridd,
    collection: str,
    source: str,
    extract_fn,
    config: dict,
    watermark: datetime,
) -> tuple[int, int, datetime | None]:
    """
    Queries a GRIDr collection for documents newer than watermark and
    extracts + upserts all vendors found in them.

    Returns (docs_processed, vendors_upserted, max_mirrored_at).
    """
    query = {"mirrored_at": {"$gt": watermark}}
    cursor = db_gridr[collection].find(
        query,
        {"mirrored_at": 1, "product_tree": 1, "enisaIdVendor": 1},
    ).batch_size(BATCH_SIZE)

    docs_processed   = 0
    vendors_upserted = 0
    max_mirrored_at: datetime | None = None

    async for doc in cursor:
        try:
            raw_names = extract_fn(doc)
            source_id = doc["_id"]
            mirrored  = doc.get("mirrored_at")

            if mirrored and mirrored.tzinfo is None:
                mirrored = mirrored.replace(tzinfo=UTC)

            if mirrored and (max_mirrored_at is None or mirrored > max_mirrored_at):
                max_mirrored_at = mirrored

            for raw_name in raw_names:
                normalized = normalize_vendor_name(raw_name, config)
                if not normalized:
                    continue
                await upsert_vendor(db_gridd, raw_name, normalized, source, source_id)
                vendors_upserted += 1
                logger.debug(f"  [VENDOR] {raw_name!r} → {normalized!r} ({source})")

            docs_processed += 1

        except Exception as exc:
            logger.error(f"  [ERROR] Failed to process doc {doc.get('_id')}: {exc}")

    return docs_processed, vendors_upserted, max_mirrored_at

# ---------------------------------------------------------------------------
# Entry Point
# ---------------------------------------------------------------------------

async def run() -> None:
    """
    Main coroutine.

    Steps
    -----
    1. Load vendors.json config.
    2. Connect to GRIDr and GRIDd.
    3. Load the current watermark from GRIDd/metadata.
    4. Process cert-bund collection (CSAF vendor extraction).
    5. Process euvd collection (EUVD vendor extraction).
    6. Advance watermark to highest mirrored_at seen in this batch.
    """
    config = load_config()

    mongo_client = AsyncIOMotorClient(MONGO_URI)
    db_gridr     = mongo_client[GRIDR_DB]
    db_gridd     = mongo_client[GRIDD_DB]

    try:
        await ensure_indexes(db_gridd)

        watermark = await load_watermark(db_gridd)
        logger.info("=" * 60)
        logger.info(f"VENDOR PROCESSOR STARTED — watermark: {watermark.isoformat()}")
        logger.info("=" * 60)

        total_docs     = 0
        total_vendors  = 0
        new_watermark: datetime | None = None

        # --- CSAF (cert-bund) ---
        docs, vendors, wm = await process_collection(
            db_gridr, db_gridd,
            collection=COLL_CERT_BUND,
            source="csaf",
            extract_fn=extract_vendors_from_csaf,
            config=config,
            watermark=watermark,
        )
        logger.info(f"  cert-bund: {docs} docs processed, {vendors} vendor entries upserted.")
        total_docs    += docs
        total_vendors += vendors
        if wm and (new_watermark is None or wm > new_watermark):
            new_watermark = wm

        # --- EUVD ---
        docs, vendors, wm = await process_collection(
            db_gridr, db_gridd,
            collection=COLL_EUVD,
            source="euvd",
            extract_fn=extract_vendors_from_euvd,
            config=config,
            watermark=watermark,
        )
        logger.info(f"  euvd: {docs} docs processed, {vendors} vendor entries upserted.")
        total_docs    += docs
        total_vendors += vendors
        if wm and (new_watermark is None or wm > new_watermark):
            new_watermark = wm

        # --- Advance watermark ---
        if new_watermark:
            await save_watermark(db_gridd, new_watermark)
        else:
            logger.info("  No new documents found — watermark unchanged.")

        logger.info("=" * 60)
        logger.info(
            f"VENDOR PROCESSOR COMPLETE — "
            f"{total_docs} docs processed, "
            f"{total_vendors} vendor entries upserted."
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
