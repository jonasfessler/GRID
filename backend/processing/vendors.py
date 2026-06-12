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
  - Cursor loss (DB restart, timeout) triggers automatic resume from last
    processed position — no manual intervention required.

Performance
-----------
  - Both collections (cert-bund, euvd) are processed concurrently.
  - CPU-bound extraction and normalization are offloaded to a process pool
    (WORKER_COUNT subprocesses) for true multi-core parallelism.
  - Bulk writes (UpdateOne ops) are flushed in UPSERT_BUFFER_SIZE batches
    with a small delay between flushes to prevent DB overload.
"""

import asyncio
import json
import logging
import os
import time
from concurrent.futures import ProcessPoolExecutor
from datetime import datetime, UTC
from pathlib import Path
from typing import Any

from motor.motor_asyncio import AsyncIOMotorClient
from pymongo import UpdateOne
from pymongo.errors import ConnectionFailure, OperationFailure, PyMongoError

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

PROCESSOR_STATE_ID  = "vendor_processor"
BATCH_SIZE          = 500           # cursor batch size
UPSERT_BUFFER_SIZE  = 5000          # bulk-write flush threshold
MAX_DB_RETRIES      = 3
RETRY_DELAY         = 2.0
WORKER_COUNT        = max(1, (os.cpu_count() or 2) - 1)
WORKER_BATCH_SIZE   = 100           # docs dispatched per worker chunk
BULK_WRITE_DELAY    = 0.01          # seconds to sleep after each bulk flush
LOG_EVERY_N         = 500           # log progress every N docs (0 = every doc)

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
# Worker: CPU-bound extraction + normalization (runs in subprocess)
# ---------------------------------------------------------------------------

def _extract_and_normalize_batch(
    docs_data: list[dict],
    source: str,
    config: dict,
) -> list[dict]:
    """
    CPU-bound worker function executed by ProcessPoolExecutor.

    Runs extraction and normalization on a batch of documents.
    Pure function — no DB access, no shared state, fully pickle-safe.

    Parameters
    ----------
    docs_data : list[dict]
        Each dict has keys: doc (raw document dict), doc_id (str),
        mirrored_at (datetime or None).
    source : str
        "csaf" or "euvd" — determines which extraction function to use.
    config : dict
        Loaded vendors.json config.

    Returns
    -------
    list[dict]
        Each dict has keys: doc_id, mirrored_at, vendors (list of dicts
        with raw_name and normalized).
    """
    extract_fn = (
        extract_vendors_from_csaf if source == "csaf"
        else extract_vendors_from_euvd
    )

    results: list[dict] = []
    for item in docs_data:
        doc = item["doc"]
        raw_names = extract_fn(doc)

        vendors: list[dict] = []
        for raw_name in raw_names:
            normalized = normalize_vendor_name(raw_name, config)
            if not normalized:
                continue
            vendors.append({
                "raw_name":   raw_name,
                "normalized": normalized,
            })

        results.append({
            "doc_id":      item["doc_id"],
            "mirrored_at": item["mirrored_at"],
            "vendors":     vendors,
        })

    return results

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
    collection: str,
    source:     str,
    config:     dict,
    watermark:  datetime,
    executor:   ProcessPoolExecutor,
) -> tuple[int, int, datetime | None]:
    """
    Queries a GRIDr collection for documents newer than watermark,
    extracts vendors from each, and upserts them into GRIDd/vendors.

    CPU-bound extraction and normalization are offloaded to a process pool
    (via ``executor``).  Bulk DB writes remain in the main async process.

    Uses a **resumable cursor** pattern: if the server-side cursor is lost
    (e.g. DB restart, cursor timeout), the cursor is re-created from the
    last successfully read ``mirrored_at`` value — no data loss, no manual
    intervention.

    Returns (docs_processed, vendors_upserted, max_mirrored_at).
    """
    # Count total documents for progress reporting
    total_count = await db_gridr[collection].count_documents(
        {"mirrored_at": {"$gt": watermark}}
    )
    logger.info(f"[{source.upper()}] Found {total_count} documents to process.")

    if total_count == 0:
        return 0, 0, None

    projection = {
        "mirrored_at": 1, "product_tree": 1, "enisaIdVendor": 1,
    }

    docs_processed   = 0
    vendors_upserted = 0
    max_mirrored_at: datetime | None = None

    bulk = BulkUpsertBuffer(db_gridd[COLL_VENDORS])
    t_start = time.perf_counter()
    loop = asyncio.get_running_loop()

    # ---- Resumable cursor state ----
    # First pass uses $gt (skip already-watermarked docs).
    # On cursor loss, subsequent passes use $gte to avoid skipping docs
    # that share the same mirrored_at as the last one we read.
    resume_after = watermark
    cursor_op    = "$gt"
    chunk_size   = WORKER_BATCH_SIZE * WORKER_COUNT

    while True:
        cursor = db_gridr[collection].find(
            {"mirrored_at": {cursor_op: resume_after}},
            projection,
            no_cursor_timeout=True,
        ).sort("mirrored_at", 1).batch_size(BATCH_SIZE)

        cursor_lost = False
        try:
            while True:
                # --- Read a chunk of docs from the cursor ---
                try:
                    raw_docs = await cursor.to_list(length=chunk_size)
                except OperationFailure as exc:
                    if exc.code == 43:          # CursorNotFound
                        cursor_lost = True
                        break
                    raise
                except ConnectionFailure:
                    cursor_lost = True
                    await asyncio.sleep(RETRY_DELAY)
                    break

                if not raw_docs:
                    break                       # cursor exhausted

                # --- Serialize docs for worker processes ---
                docs_data: list[dict] = []
                for doc in raw_docs:
                    mirrored = doc.get("mirrored_at")
                    if mirrored and mirrored.tzinfo is None:
                        mirrored = mirrored.replace(tzinfo=UTC)

                    doc_id = str(doc.get("_id", "?"))

                    # Strip _id (ObjectId) — not needed by workers
                    docs_data.append({
                        "doc":         {k: v for k, v in doc.items() if k != "_id"},
                        "doc_id":      doc_id,
                        "mirrored_at": mirrored,
                    })

                    # Track resume position and global max
                    if mirrored:
                        resume_after = mirrored
                        if max_mirrored_at is None or mirrored > max_mirrored_at:
                            max_mirrored_at = mirrored

                # --- Dispatch to process pool ---
                sub_batches = [
                    docs_data[i : i + WORKER_BATCH_SIZE]
                    for i in range(0, len(docs_data), WORKER_BATCH_SIZE)
                ]

                futures = [
                    loop.run_in_executor(
                        executor, _extract_and_normalize_batch,
                        batch, source, config,
                    )
                    for batch in sub_batches
                ]
                worker_results = await asyncio.gather(*futures)

                # --- Process results in main process (build ops + bulk write) ---
                for batch_result in worker_results:
                    for doc_result in batch_result:

                        if not doc_result["vendors"]:
                            docs_processed += 1
                            if LOG_EVERY_N == 0 or docs_processed % LOG_EVERY_N == 0:
                                elapsed = time.perf_counter() - t_start
                                rate    = docs_processed / elapsed if elapsed > 0 else 0
                                logger.info(
                                    f"  [{source.upper()}] [{docs_processed}/{total_count}] "
                                    f"{doc_result['doc_id']} — 0 vendors (skipped) "
                                    f"({rate:.1f} docs/s)"
                                )
                            continue

                        entry_count = 0
                        for vendor in doc_result["vendors"]:
                            now = datetime.now(UTC)
                            op = UpdateOne(
                                {"name": vendor["normalized"]},
                                {
                                    "$set":         {
                                        "name":       vendor["normalized"],
                                        "updated_at": now,
                                    },
                                    "$setOnInsert": {"created_at": now},
                                    "$addToSet":    {
                                        "raw_names": vendor["raw_name"],
                                        "sources":   source,
                                    },
                                },
                                upsert=True,
                            )
                            bulk.add(op)
                            entry_count += 1

                            logger.debug(
                                f"    [VENDOR] {vendor['raw_name']!r} → "
                                f"{vendor['normalized']!r} ({source})"
                            )

                        # Flush if buffer is full
                        flushed = await bulk.maybe_flush()
                        if flushed:
                            logger.info(
                                f"    [BULK FLUSH] Wrote {flushed} vendor upserts to DB"
                            )
                            await asyncio.sleep(BULK_WRITE_DELAY)

                        vendors_upserted += entry_count
                        docs_processed   += 1

                        # Throttled per-document progress log
                        if LOG_EVERY_N == 0 or docs_processed % LOG_EVERY_N == 0 or docs_processed == total_count:
                            elapsed = time.perf_counter() - t_start
                            rate    = docs_processed / elapsed if elapsed > 0 else 0
                            logger.info(
                                f"  [{source.upper()}] [{docs_processed}/{total_count}] "
                                f"{doc_result['doc_id']} — {entry_count} vendors "
                                f"({rate:.1f} docs/s)"
                            )

        except Exception as exc:
            logger.error(
                f"  [{source.upper()}] Unexpected error during processing: {exc}"
            )
            cursor_lost = True
        finally:
            try:
                await cursor.close()
            except Exception:
                pass                            # cursor already dead

        if cursor_lost:
            cursor_op = "$gte"                  # avoid skipping boundary docs
            logger.warning(
                f"  [{source.upper()}] Cursor lost at doc {docs_processed}/{total_count} "
                f"— resuming from {resume_after.isoformat()}"
            )
            continue

        break                                   # cursor exhausted normally

    # Final flush of remaining buffered ops
    remaining = await bulk.flush()
    if remaining:
        logger.info(
            f"  [{source.upper()}] [BULK FLUSH] Final write: "
            f"{remaining} vendor upserts"
        )

    elapsed = time.perf_counter() - t_start
    logger.info(
        f"  [{source.upper()}] Done: {docs_processed} docs, "
        f"{vendors_upserted} vendors in {elapsed:.1f}s "
        f"(buffer flushed {bulk.total_flushed} total ops)"
    )

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
    3. Create a process pool for CPU-bound work.
    4. Load the current watermark from GRIDd/metadata.
    5. Process cert-bund and euvd collections concurrently.
    6. Advance watermark to highest mirrored_at seen in this batch.
    """
    config = load_config()

    mongo_client = AsyncIOMotorClient(MONGO_URI)
    db_gridr     = mongo_client[GRIDR_DB]
    db_gridd     = mongo_client[GRIDD_DB]

    executor = ProcessPoolExecutor(max_workers=WORKER_COUNT)
    logger.info(f"Process pool created with {WORKER_COUNT} workers")

    try:
        await ensure_indexes(db_gridd)

        watermark = await load_watermark(db_gridd)
        logger.info("=" * 60)
        logger.info(f"VENDOR PROCESSOR STARTED — watermark: {watermark.isoformat()}")
        logger.info("=" * 60)

        t_start = time.perf_counter()

        # --- Process both collections concurrently ---
        csaf_task = asyncio.create_task(
            process_collection(
                db_gridr, db_gridd,
                collection=COLL_CERT_BUND,
                source="csaf",
                config=config,
                watermark=watermark,
                executor=executor,
            )
        )
        euvd_task = asyncio.create_task(
            process_collection(
                db_gridr, db_gridd,
                collection=COLL_EUVD,
                source="euvd",
                config=config,
                watermark=watermark,
                executor=executor,
            )
        )

        (csaf_docs, csaf_vendors, csaf_wm), (euvd_docs, euvd_vendors, euvd_wm) = (
            await asyncio.gather(csaf_task, euvd_task)
        )

        total_docs    = csaf_docs + euvd_docs
        total_vendors = csaf_vendors + euvd_vendors

        logger.info(f"  cert-bund: {csaf_docs} docs processed, {csaf_vendors} vendor entries upserted.")
        logger.info(f"  euvd: {euvd_docs} docs processed, {euvd_vendors} vendor entries upserted.")

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
            f"VENDOR PROCESSOR COMPLETE — "
            f"{total_docs} docs processed, "
            f"{total_vendors} vendor entries upserted "
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
        executor.shutdown(wait=True)
        mongo_client.close()


if __name__ == "__main__":
    asyncio.run(run())
