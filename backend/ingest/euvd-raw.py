"""
euvd-raw-new.py
===============
GRIDr Raw Ingest: Mirrors all ENISA EUVD entries into MongoDB
database GRIDr / collection euvd.

Philosophy (GRIDr / Medallion Architecture)
-------------------------------------------
  - Zero-Processing: Each JSON item from the ENISA API is stored completely
    and without any transformation.
  - Three metadata fields are added at ingest time:
      • mirrored_at          — UTC timestamp of the ingest operation
      • source_url           — API URL used to fetch this item's page
      • _date_updated_parsed — Parsed UTC datetime of dateUpdated (for indexed
                               change-detection; not present in raw EUVD payload)
  - Idempotency: item.id is the unique key. Per-item change detection via
    _date_updated_parsed prevents unnecessary DB writes.

Run Modes
---------
  RESUME    — A previous run was interrupted. Continues from the last
              successfully completed page (checkpoint in GRIDr/metadata).

  DELTA     — A previous run completed successfully. Paginates from page 0
              and stops as soon as a full page contains only items that are
              already up-to-date in the DB (timestamp cutoff). Per-item
              change detection acts as a safety net.

  FULL SEED — No previous state found. Processes all pages from 0 to end.

State Documents (GRIDr / metadata collection)
----------------------------------------------
  "euvd_run_state"  — Written after each page; cleared on successful finish.
                      Enables RESUME after any abort or crash.
  "euvd_last_run"   — Written on successful finish. Enables DELTA on next run.

Fault Tolerance
---------------
  - Token-Bucket RateLimiter: max 1 req / REQUEST_SPACING seconds (ENISA).
  - Retry + exponential backoff on 403 / 429 / 5xx / Timeout / ConnectError.
  - Script aborts are safe: upsert=True + checkpoint → clean resume.
"""

import asyncio
import httpx
import logging
import random
from datetime import datetime, UTC
from typing import Any

from motor.motor_asyncio import AsyncIOMotorClient

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

MONGO_URI  = "mongodb://localhost:27017/"
DB_NAME    = "GRIDr"
COLL_NAME  = "euvd"
COLL_META  = "metadata"

ENISA_SEARCH_URL = "https://euvdservices.enisa.europa.eu/api/search"
PAGE_SIZE        = 100

MAX_CONCURRENT_PAGES = 3       # Conservative — ENISA rate-limits aggressively
REQUEST_SPACING      = 1.5     # Seconds between requests (token bucket)

MAX_RETRIES    = 6
BACKOFF_BASE   = 4.0
BACKOFF_CAP    = 120.0
BACKOFF_JITTER = 0.4

RETRIABLE_CODES = {403, 429, 500, 502, 503, 504}

# State document IDs in metadata collection
RUN_STATE_ID = "euvd_run_state"   # In-progress checkpoint
LAST_RUN_ID  = "euvd_last_run"    # Last successful run info

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/123.0.0.0 Safari/537.36 GRID-EUVD-Raw/1.0"
    ),
    "Accept": "application/json",
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
# Token-Bucket RateLimiter
# ---------------------------------------------------------------------------

class RateLimiter:
    """Async Token-Bucket Rate Limiter. Guarantees max `rate` requests/second."""

    def __init__(self, rate: float, burst: int) -> None:
        self._rate   = rate
        self._burst  = float(burst)
        self._tokens = float(burst)
        self._last   = 0.0
        self._lock   = asyncio.Lock()

    async def acquire(self) -> None:
        async with self._lock:
            now            = asyncio.get_event_loop().time()
            elapsed        = now - self._last if self._last else 0.0
            self._last     = now
            self._tokens   = min(self._burst, self._tokens + elapsed * self._rate)
            if self._tokens >= 1.0:
                self._tokens -= 1.0
            else:
                wait         = (1.0 - self._tokens) / self._rate
                self._tokens = 0.0
                self._last   = now + wait
                await asyncio.sleep(wait)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _backoff_delay(attempt: int) -> float:
    """Exponential backoff with full jitter, capped at BACKOFF_CAP."""
    raw    = BACKOFF_BASE * (2 ** attempt)
    jitter = raw * BACKOFF_JITTER * (2 * random.random() - 1)
    return min(BACKOFF_CAP, max(0.5, raw + jitter))


def _parse_enisa_date(date_str: str | None) -> datetime | None:
    """Parses ENISA date format 'Apr 17, 2026, 9:39:54 PM' to UTC datetime."""
    if not date_str:
        return None
    try:
        return datetime.strptime(date_str, "%b %d, %Y, %I:%M:%S %p").replace(tzinfo=UTC)
    except (ValueError, TypeError):
        return None

# ---------------------------------------------------------------------------
# State Management  (GRIDr / metadata)
# ---------------------------------------------------------------------------

async def _load_run_state(db) -> dict | None:
    """Returns the checkpoint of an in-progress run, or None."""
    return await db[COLL_META].find_one({"_id": RUN_STATE_ID})


async def _save_run_state(
    db,
    last_completed_page: int,
    total_pages:         int,
    run_started_at:      datetime,
    total_at_start:      int,
) -> None:
    """Saves per-page checkpoint so a crashed run can be resumed."""
    await db[COLL_META].update_one(
        {"_id": RUN_STATE_ID},
        {"$set": {
            "last_completed_page": last_completed_page,
            "total_pages":         total_pages,
            "run_started_at":      run_started_at,
            "total_at_start":      total_at_start,
            "updated_at":          datetime.now(UTC),
        }},
        upsert=True,
    )


async def _clear_run_state(db) -> None:
    """Deletes the in-progress checkpoint after a successful finish."""
    await db[COLL_META].delete_one({"_id": RUN_STATE_ID})
    logger.info("Run state cleared.")


async def _load_last_run(db) -> datetime | None:
    """Returns the timestamp of the last successful run, or None."""
    doc = await db[COLL_META].find_one({"_id": LAST_RUN_ID})
    return doc.get("completed_at") if doc else None


async def _save_last_run(db, completed_at: datetime, stats: dict) -> None:
    """Persists the successful run timestamp and summary stats."""
    await db[COLL_META].update_one(
        {"_id": LAST_RUN_ID},
        {"$set": {"completed_at": completed_at, **stats}},
        upsert=True,
    )
    logger.info(f"Last run state saved: {completed_at.isoformat()}")

# ---------------------------------------------------------------------------
# Index Setup
# ---------------------------------------------------------------------------

async def ensure_indexes(db) -> None:
    """Creates indexes on the euvd collection (idempotent)."""
    await db[COLL_NAME].create_index("id", unique=True)
    await db[COLL_NAME].create_index("_date_updated_parsed")
    logger.info("Indexes on 'id' and '_date_updated_parsed' verified.")

# ---------------------------------------------------------------------------
# Raw Ingest — single item
# ---------------------------------------------------------------------------

async def store_raw_item(item: dict[str, Any], source_url: str, db) -> str:
    """
    Stores a single EUVD item unchanged in GRIDr.

    Change Detection
    ----------------
    Compares incoming dateUpdated with the stored _date_updated_parsed:
      Not in DB         → inserted
      Incoming is newer → updated
      Same or older     → skipped (no DB write)

    Returns: 'inserted' | 'updated' | 'skipped'
    """
    euvd_id = (item.get("id") or "").strip()
    if not euvd_id:
        logger.warning("  [SKIP] Item has no 'id' field.")
        return "skipped"

    incoming_date = _parse_enisa_date(item.get("dateUpdated"))

    # Projection: fetch only the change-detection field (fast, indexed lookup)
    existing = await db[COLL_NAME].find_one(
        {"id": euvd_id},
        {"_date_updated_parsed": 1},
    )

    if existing:
        stored_date = existing.get("_date_updated_parsed")
        # MongoDB/Motor may return naive datetimes even for UTC-stored values.
        # Normalize to UTC-aware before comparing to avoid TypeError.
        if stored_date and stored_date.tzinfo is None:
            stored_date = stored_date.replace(tzinfo=UTC)
        if stored_date and incoming_date and incoming_date <= stored_date:
            logger.debug(f"  [SKIP] {euvd_id} — unchanged.")
            return "skipped"

    document = {
        **item,
        "mirrored_at":          datetime.now(UTC),
        "source_url":           source_url,
        "_date_updated_parsed": incoming_date,
    }
    await db[COLL_NAME].update_one(
        {"id": euvd_id},
        {"$set": document},
        upsert=True,
    )

    action = "inserted" if not existing else "updated"
    logger.info(f"  [{action.upper()}] {euvd_id}")
    return action

# ---------------------------------------------------------------------------
# HTTP Layer with Retry & Backoff
# ---------------------------------------------------------------------------

async def fetch_page(
    client:    httpx.AsyncClient,
    page:      int,
    semaphore: asyncio.Semaphore,
    limiter:   RateLimiter,
) -> dict[str, Any] | None:
    """
    Fetches one page from ENISA /api/search with retry + backoff.
    Returns the parsed JSON dict or None on permanent failure.
    """
    params = {"size": PAGE_SIZE, "page": page}

    async with semaphore:
        for attempt in range(MAX_RETRIES + 1):
            await limiter.acquire()
            try:
                resp = await client.get(ENISA_SEARCH_URL, params=params, timeout=30.0)

                if resp.status_code == 200:
                    return resp.json()

                if resp.status_code in RETRIABLE_CODES:
                    if attempt < MAX_RETRIES:
                        delay = _backoff_delay(attempt)
                        logger.warning(
                            f"  [HTTP {resp.status_code}] page {page} "
                            f"(attempt {attempt + 1}/{MAX_RETRIES}) — retry in {delay:.1f}s"
                        )
                        await asyncio.sleep(delay)
                        continue
                    logger.error(f"  [FAILED] page {page} — HTTP {resp.status_code} after {MAX_RETRIES} retries.")
                    return None

                logger.warning(f"  [HTTP {resp.status_code}] page {page} — non-retriable, skipped.")
                return None

            except httpx.TimeoutException:
                if attempt < MAX_RETRIES:
                    delay = _backoff_delay(attempt)
                    logger.warning(f"  [TIMEOUT] page {page} (attempt {attempt + 1}/{MAX_RETRIES}) — retry in {delay:.1f}s")
                    await asyncio.sleep(delay)
                else:
                    logger.error(f"  [FAILED] page {page} — timed out after {MAX_RETRIES} retries.")
                    return None

            except (httpx.ConnectError, httpx.RemoteProtocolError) as exc:
                if attempt < MAX_RETRIES:
                    delay = _backoff_delay(attempt)
                    logger.warning(f"  [CONN ERROR] page {page}: {exc} (attempt {attempt + 1}/{MAX_RETRIES}) — retry in {delay:.1f}s")
                    await asyncio.sleep(delay)
                else:
                    logger.error(f"  [FAILED] page {page} — connection error after {MAX_RETRIES} retries: {exc}")
                    return None

            except Exception as exc:
                logger.error(f"  [ERROR] page {page}: {exc}")
                return None

    return None

# ---------------------------------------------------------------------------
# Page Processor
# ---------------------------------------------------------------------------

async def process_page(
    data:       dict[str, Any],
    source_url: str,
    db,
) -> tuple[int, int, int]:
    """
    Stores all items from one fetched page.
    Returns (inserted, updated, skipped) counts.
    """
    items = data.get("items") or []
    if not items:
        return 0, 0, 0

    results = await asyncio.gather(
        *[store_raw_item(item, source_url, db) for item in items],
        return_exceptions=True,
    )

    inserted = updated = skipped = 0
    for r in results:
        if isinstance(r, Exception):
            logger.error(f"  [ERROR] Unexpected exception: {r}")
            skipped += 1
        elif r == "inserted":
            inserted += 1
        elif r == "updated":
            updated += 1
        else:
            skipped += 1

    return inserted, updated, skipped


def _page_is_all_old(data: dict[str, Any], since: datetime) -> bool:
    """
    Returns True if every item on the page has dateUpdated <= since.
    Used for delta early-termination: once a full page is "old", we can stop.
    """
    items = data.get("items") or []
    if not items:
        return True
    for item in items:
        item_date = _parse_enisa_date(item.get("dateUpdated"))
        if item_date is None or item_date > since:
            return False
    return True

# ---------------------------------------------------------------------------
# Entry Point
# ---------------------------------------------------------------------------

async def run_import() -> None:
    """
    Main coroutine. Determines run mode, processes pages sequentially
    (with semaphore + RateLimiter), checkpoints after each page, and
    saves the last-run state on successful completion.

    Run Modes
    ---------
    RESUME    — euvd_run_state found → continue from last_completed_page + 1
    DELTA     — euvd_last_run found  → stop when a full page is all-old
    FULL SEED — no state             → process all pages
    """
    mongo_client = AsyncIOMotorClient(MONGO_URI)
    db           = mongo_client[DB_NAME]

    try:
        await ensure_indexes(db)

        semaphore = asyncio.Semaphore(MAX_CONCURRENT_PAGES)
        limiter   = RateLimiter(rate=1.0 / REQUEST_SPACING, burst=1)

        # Load existing state
        run_state = await _load_run_state(db)
        last_run  = await _load_last_run(db)

        async with httpx.AsyncClient(headers=HEADERS, verify=True) as client:

            # ----------------------------------------------------------------
            # Fetch page 0 — always needed to get the current total count
            # ----------------------------------------------------------------
            logger.info("Fetching page 0 from ENISA EUVD...")
            first_data = await fetch_page(client, 0, semaphore, limiter)
            if not first_data:
                logger.error("CRITICAL: Could not fetch page 0 — aborting.")
                return

            total_entries = first_data.get("total", 0)
            total_pages   = (total_entries + PAGE_SIZE - 1) // PAGE_SIZE

            # ----------------------------------------------------------------
            # Determine mode and start page
            # ----------------------------------------------------------------
            run_started_at: datetime

            if run_state:
                # RESUME: continue from the page after the last checkpoint
                start_page     = run_state["last_completed_page"] + 1
                run_started_at = run_state["run_started_at"]
                total_at_start = run_state.get("total_at_start", total_entries)
                mode           = "RESUME"
                logger.info("=" * 60)
                logger.info(
                    f"MODE: RESUME — continuing from page {start_page}/{total_pages - 1} "
                    f"(run started at {run_started_at.isoformat()})"
                )
            else:
                start_page     = 0
                run_started_at = datetime.now(UTC)
                total_at_start = total_entries
                mode           = "DELTA" if last_run else "FULL SEED"
                logger.info("=" * 60)
                if last_run:
                    logger.info(f"MODE: DELTA — last successful run: {last_run.isoformat()}")
                else:
                    logger.info(f"MODE: FULL SEED — {total_entries:,} entries across {total_pages:,} pages")

            logger.info("=" * 60)

            # ----------------------------------------------------------------
            # Page loop
            # ----------------------------------------------------------------
            total_inserted = total_updated = total_skipped = total_failed = 0

            for page in range(start_page, total_pages):
                page_url = f"{ENISA_SEARCH_URL}?size={PAGE_SIZE}&page={page}"

                # Use already-fetched page 0 data if applicable
                if page == 0 and not run_state:
                    data = first_data
                else:
                    data = await fetch_page(client, page, semaphore, limiter)

                if data is None:
                    logger.warning(f"  [SKIP] page {page} could not be fetched — checkpoint saved, continuing.")
                    # Save checkpoint even on failure so next resume skips this page
                    await _save_run_state(db, page, total_pages, run_started_at, total_at_start)
                    total_failed += PAGE_SIZE
                    continue

                # Delta early-termination: stop if the whole page is already up-to-date
                if mode == "DELTA" and last_run and _page_is_all_old(data, last_run):
                    logger.info(
                        f"  [DELTA CUTOFF] page {page} — all items already up-to-date. "
                        f"Stopping early."
                    )
                    break

                ins, upd, skp = await process_page(data, page_url, db)
                total_inserted += ins
                total_updated  += upd
                total_skipped  += skp

                # Save checkpoint after each successfully processed page
                await _save_run_state(db, page, total_pages, run_started_at, total_at_start)

                if page % 10 == 0 or page == total_pages - 1:
                    logger.info(
                        f"  Progress: page {page}/{total_pages - 1} | "
                        f"+{ins} inserted / +{upd} updated / {skp} skipped this page | "
                        f"Total so far: {total_inserted}/{total_updated}/{total_skipped}"
                    )

            # ----------------------------------------------------------------
            # Finalize
            # ----------------------------------------------------------------
            stats = {
                "total_inserted": total_inserted,
                "total_updated":  total_updated,
                "total_skipped":  total_skipped,
                "total_failed":   total_failed,
                "mode":           mode,
            }

            await _clear_run_state(db)
            await _save_last_run(db, datetime.now(UTC), stats)

            logger.info("=" * 60)
            logger.info(
                f"RAW INGEST COMPLETE ({mode}) — "
                f"{total_inserted:,} inserted, "
                f"{total_updated:,} updated, "
                f"{total_skipped:,} unchanged/skipped, "
                f"{total_failed:,} failed "
                f"(out of {total_entries:,} total entries)."
            )

    except Exception as exc:
        logger.error(f"CRITICAL: Unexpected error in run_import: {exc}")
        raise

    finally:
        mongo_client.close()


if __name__ == "__main__":
    asyncio.run(run_import())
