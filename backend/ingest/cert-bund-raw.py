"""
cert-bund-raw.py
================
GRIDr Raw Ingest: Mirrors all CERT-Bund CSAF advisories into MongoDB
database GRIDr / collection cert-bund.

Philosophy (GRIDr / Medallion Architecture)
-------------------------------------------
  - Zero-Processing: The JSON document delivered by the CERT-Bund API is
    stored completely and without any transformation.
  - No extraction of vendors, products, or advisory structures.
  - Two metadata fields are added at ingest time:
      • mirrored_at  — UTC timestamp of the ingest operation (datetime)
      • source_url   — URL from which the JSON document was fetched
  - Idempotency: tracking.id is used as a unique key. Before writing,
    document.tracking.current_release_date is compared with the stored value.
    Documents that have not changed are skipped entirely (no DB write).
    New or updated documents are upserted.

Data Flow
---------
  index.txt (CERT-Bund)
      └─► fetch_and_store()
              └─► cert-bund  (GRIDr — full raw payload + metadata)

Fault Tolerance
---------------
  - Retry with exponential backoff + jitter on 403 / 429 / 5xx responses.
  - Retry on network timeouts and transient connection errors.
  - Non-retriable errors (e.g. 404) are logged and skipped immediately.
  - Script aborts are safe: upsert=True guarantees that a full re-run
    will update existing documents without creating duplicates.

Performance
-----------
  - motor.motor_asyncio  for non-blocking DB operations
  - httpx.AsyncClient    for non-blocking HTTP requests
  - asyncio.Semaphore    limits concurrent requests to MAX_CONCURRENT_REQUESTS
"""

import asyncio
import httpx
import logging
import random
import urllib.parse
from datetime import datetime, UTC

from motor.motor_asyncio import AsyncIOMotorClient

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

MONGO_URI = "mongodb://localhost:27017/"
DB_NAME   = "GRIDr"
COLL_NAME = "cert-bund"

GLOBAL_INDEX_URL = "https://wid.cert-bund.de/.well-known/csaf/white/index.txt"
BASE_URL_WHITE   = "https://wid.cert-bund.de/.well-known/csaf/white/"

# Maximum number of concurrent HTTP requests
MAX_CONCURRENT_REQUESTS = 15

# Retry / Backoff settings
MAX_RETRIES  = 5      # Maximum number of retry attempts per advisory
BACKOFF_BASE = 2.0    # Base delay in seconds (doubles each attempt)
BACKOFF_CAP  = 60.0   # Maximum delay cap in seconds
BACKOFF_JITTER = 0.3  # ±30% jitter to avoid thundering herd

# HTTP status codes that should trigger a retry
RETRIABLE_CODES = {403, 429, 500, 502, 503, 504}

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/123.0.0.0 Safari/537.36 GRID-CERT-BUND-Raw/1.0"
    )
}

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
# Backoff Helper
# ---------------------------------------------------------------------------

def _backoff_delay(attempt: int) -> float:
    """
    Calculates exponential backoff delay with full jitter.

    Formula: min(BACKOFF_CAP, BACKOFF_BASE * 2^attempt) * (1 ± BACKOFF_JITTER)

    Example delays (without jitter):
      Attempt 0 →  2s
      Attempt 1 →  4s
      Attempt 2 →  8s
      Attempt 3 → 16s
      Attempt 4 → 32s  (capped at BACKOFF_CAP=60s)
    """
    raw    = BACKOFF_BASE * (2 ** attempt)
    jitter = raw * BACKOFF_JITTER * (2 * random.random() - 1)
    return min(BACKOFF_CAP, max(0.5, raw + jitter))

# ---------------------------------------------------------------------------
# Index Setup
# ---------------------------------------------------------------------------

async def ensure_indexes(db) -> None:
    """
    Creates indexes on the cert-bund collection (idempotent).

    Indexes
    -------
    document.tracking.id                 — unique key for upserts
    document.tracking.current_release_date — used for change-detection lookups
    """
    await db[COLL_NAME].create_index("document.tracking.id", unique=True)
    await db[COLL_NAME].create_index("document.tracking.current_release_date")
    logger.info("Indexes on 'document.tracking.id' and 'current_release_date' verified.")

# ---------------------------------------------------------------------------
# Raw Ingest
# ---------------------------------------------------------------------------

async def store_raw_document(data: dict, source_url: str, db) -> str:
    """
    Stores a CSAF JSON document completely and unchanged in GRIDr.

    Change Detection
    ----------------
    Before writing to the database, the incoming document.tracking.current_release_date
    is compared with the value already stored for this tracking.id.
      - Not in DB yet  → inserted (upsert)
      - Stored date is older  → updated ($set)
      - Stored date is equal or newer  → skipped (no DB write)

    This avoids unnecessary writes and makes repeated runs efficient.

    Metadata Fields Added
    ---------------------
      • mirrored_at  — UTC datetime of the ingest operation
      • source_url   — URL from which the document was fetched

    Returns
    -------
    'inserted'  if the document was new.
    'updated'   if the document existed and was newer.
    'skipped'   if the document was unchanged or tracking.id was missing.
    """
    tracking    = data.get("document", {}).get("tracking", {})
    tracking_id = tracking.get("id")

    if not tracking_id:
        logger.warning(f"  [SKIP] No tracking.id found in document from {source_url!r}")
        return "skipped"

    incoming_release_date_str = tracking.get("current_release_date")

    # --- Change detection: look up only the release date, not the full document ---
    existing = await db[COLL_NAME].find_one(
        {"document.tracking.id": tracking_id},
        {"document.tracking.current_release_date": 1},  # projection: fetch only this field
    )

    if existing:
        stored_date_str = (
            existing.get("document", {})
                    .get("tracking", {})
                    .get("current_release_date")
        )
        # Skip if both dates are present and incoming is not newer
        if stored_date_str and incoming_release_date_str:
            if incoming_release_date_str <= stored_date_str:
                logger.debug(f"  [SKIP] {tracking_id} — unchanged (release date: {stored_date_str})")
                return "skipped"

    # --- Write: document is new or has been updated ---
    document = {
        **data,
        "mirrored_at": datetime.now(UTC),
        "source_url":  source_url,
    }

    await db[COLL_NAME].update_one(
        {"document.tracking.id": tracking_id},
        {"$set": document},
        upsert=True,
    )

    action = "inserted" if not existing else "updated"
    logger.info(f"  [{action.upper()}] {tracking_id}")
    return action

# ---------------------------------------------------------------------------
# HTTP Layer with Retry & Backoff
# ---------------------------------------------------------------------------

async def fetch_and_store(
    client:    httpx.AsyncClient,
    db,
    path:      str,
    semaphore: asyncio.Semaphore,
) -> bool:
    """
    Fetches a single CSAF JSON from CERT-Bund and stores it raw in GRIDr.

    Retry Behavior
    --------------
    403 / 429 / 5xx  → Exponential backoff, retried up to MAX_RETRIES times.
    Timeout          → Exponential backoff, retried up to MAX_RETRIES times.
    Connection error → Exponential backoff, retried up to MAX_RETRIES times.
    Other 4xx        → Logged and skipped immediately (non-retriable).
    All retries exhausted → Logged as error, returns False.

    Parameters
    ----------
    client    : Shared httpx.AsyncClient instance
    db        : Motor database handle (GRIDr)
    path      : Relative path from index.txt (e.g. '2024/wid-sec-w-2024-0001.json')
    semaphore : Limits concurrent requests to MAX_CONCURRENT_REQUESTS

    Returns
    -------
    True on successful ingest, False on permanent failure.
    """
    full_url = urllib.parse.urljoin(BASE_URL_WHITE, path)

    async with semaphore:
        for attempt in range(MAX_RETRIES + 1):
            try:
                response = await client.get(full_url, timeout=15.0)

                if response.status_code == 200:
                    return await store_raw_document(response.json(), full_url, db)

                if response.status_code in RETRIABLE_CODES:
                    if attempt < MAX_RETRIES:
                        delay = _backoff_delay(attempt)
                        logger.warning(
                            f"  [HTTP {response.status_code}] {path} "
                            f"(attempt {attempt + 1}/{MAX_RETRIES}) "
                            f"— retrying in {delay:.1f}s..."
                        )
                        await asyncio.sleep(delay)
                        continue
                    # All retries exhausted
                    logger.error(
                        f"  [FAILED] {path} — HTTP {response.status_code} "
                        f"after {MAX_RETRIES} retries."
                    )
                    return "skipped"

                # Non-retriable HTTP error (e.g. 404)
                logger.warning(
                    f"  [HTTP {response.status_code}] {path} — skipped (non-retriable)."
                )
                return "skipped"

            except httpx.TimeoutException:
                if attempt < MAX_RETRIES:
                    delay = _backoff_delay(attempt)
                    logger.warning(
                        f"  [TIMEOUT] {path} "
                        f"(attempt {attempt + 1}/{MAX_RETRIES}) "
                        f"— retrying in {delay:.1f}s..."
                    )
                    await asyncio.sleep(delay)
                else:
                    logger.error(
                        f"  [FAILED] {path} — timed out after {MAX_RETRIES} retries."
                    )
                    return "skipped"

            except (httpx.ConnectError, httpx.RemoteProtocolError) as exc:
                if attempt < MAX_RETRIES:
                    delay = _backoff_delay(attempt)
                    logger.warning(
                        f"  [CONN ERROR] {path}: {exc} "
                        f"(attempt {attempt + 1}/{MAX_RETRIES}) "
                        f"— retrying in {delay:.1f}s..."
                    )
                    await asyncio.sleep(delay)
                else:
                    logger.error(
                        f"  [FAILED] {path} — connection error after "
                        f"{MAX_RETRIES} retries: {exc}"
                    )
                    return "skipped"

            except Exception as exc:
                # Unexpected errors are not retried to avoid masking bugs
                logger.error(f"  [ERROR] {path}: {exc}")
                return "skipped"

    return "skipped"  # Should not be reached

# ---------------------------------------------------------------------------
# Entry Point
# ---------------------------------------------------------------------------

async def run_import() -> None:
    """
    Main coroutine.

    Steps
    -----
    1. Connect to GRIDr and ensure indexes.
    2. Fetch index.txt from CERT-Bund and extract all JSON paths.
    3. Sort paths in descending order (newest advisories first).
    4. Fetch and store all advisories concurrently with semaphore throttling.
    5. Log a summary of results.

    Abort Safety
    ------------
    Since every write uses upsert=True, a full re-run after an abort is safe:
    already-stored documents are updated in-place, no duplicates are created.
    """
    mongo_client = AsyncIOMotorClient(MONGO_URI)
    db           = mongo_client[DB_NAME]

    try:
        await ensure_indexes(db)

        async with httpx.AsyncClient(headers=HEADERS, verify=True) as client:
            try:
                logger.info("Fetching index.txt from CERT-Bund...")
                response = await client.get(GLOBAL_INDEX_URL, timeout=20.0)
                response.raise_for_status()

                # Extract all JSON paths, process newest advisories first
                paths = [
                    line.strip()
                    for line in response.text.splitlines()
                    if line.strip().lower().endswith(".json")
                ]
                paths.sort(reverse=True)

                logger.info(
                    f"RAW INGEST STARTED — {len(paths):,} advisories found in index.txt"
                )

                semaphore = asyncio.Semaphore(MAX_CONCURRENT_REQUESTS)
                tasks     = [
                    fetch_and_store(client, db, path, semaphore)
                    for path in paths
                ]
                results: list[str] = await asyncio.gather(*tasks)

                total_inserted = sum(1 for r in results if r == "inserted")
                total_updated  = sum(1 for r in results if r == "updated")
                total_skipped  = sum(1 for r in results if r == "skipped")
                total_failed   = len(results) - total_inserted - total_updated - total_skipped

                logger.info(
                    f"RAW INGEST COMPLETE — "
                    f"{total_inserted:,} inserted, "
                    f"{total_updated:,} updated, "
                    f"{total_skipped:,} unchanged/skipped, "
                    f"{total_failed:,} failed "
                    f"(out of {len(paths):,} total)."
                )

            except httpx.HTTPStatusError as exc:
                logger.error(
                    f"CRITICAL: Failed to fetch index.txt — "
                    f"HTTP {exc.response.status_code}: {exc}"
                )
            except httpx.RequestError as exc:
                logger.error(f"CRITICAL: Network error fetching index.txt: {exc}")
            except Exception as exc:
                logger.error(f"CRITICAL: Unexpected error: {exc}")

    finally:
        mongo_client.close()


if __name__ == "__main__":
    asyncio.run(run_import())
