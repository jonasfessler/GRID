"""
euvd-raw.py
===========
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
    _date_updated_parsed prevents redundant DB writes via bulk_write filter.

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
  "euvd_run_state"  — Written after each page batch; cleared on successful
                      finish. Enables RESUME after any abort or crash.
                      Tracks the highest *contiguous* completed page so a
                      resume never re-fetches pages already checkpointed.
  "euvd_last_run"   — Written on successful finish. Enables DELTA on next run.

Performance Architecture
------------------------
  - Concurrent page fetching via asyncio.gather over WINDOW_SIZE batches.
  - Token-bucket RateLimiter shared across all concurrent fetchers so the
    total request rate never exceeds 1 / REQUEST_SPACING req/s globally.
  - Bulk DB writes: one find() (projection) + one bulk_write(ReplaceOne,
    upsert=True) per page → 2 round-trips instead of 200.
  - Change detection is performed in Python against the bulk-fetched existing
    documents, so no update is issued for unchanged items.

Fault Tolerance
---------------
  - Retry + exponential backoff on 403 / 429 / 5xx / Timeout / ConnectError.
  - Checkpoint tracks highest contiguous completed page so a resume is safe
    even when concurrent pages complete out of order.
  - Script aborts are safe: upsert=True + checkpoint → clean resume.

Tuning Guide
------------
  REQUEST_SPACING      = 0.7 → ~1.43 req/s globally. burst MUST stay at 1;
                               never set burst > 1 or concurrent windows will
                               fire simultaneously and trigger ENISA 403 storms.
                               To increase throughput, reduce REQUEST_SPACING
                               in 0.05s steps (0.6 → 0.5) only after a clean
                               full run with zero 403s.
  MAX_CONCURRENT_PAGES = 4   → Pages simultaneously in-flight. The semaphore
                               enforces this ceiling; the rate limiter (burst=1)
                               gates the actual dispatch cadence to 1 req/0.7s.
  WINDOW_SIZE = 32           → How many page coroutines are passed to a single
                               asyncio.gather() call. A larger window allows
                               faster pages to keep the semaphore slots filled
                               while slower ones retry.
"""

import asyncio
import logging
import random
from collections import defaultdict
from datetime import datetime, UTC
from typing import Any

import httpx
from motor.motor_asyncio import AsyncIOMotorClient
from pymongo import ReplaceOne

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

MONGO_URI  = "mongodb://localhost:27017/"
DB_NAME    = "GRIDr"
COLL_NAME  = "euvd"
COLL_META  = "metadata"

ENISA_SEARCH_URL = "https://euvdservices.enisa.europa.eu/api/search"
PAGE_SIZE        = 100

# --- Concurrency & Rate Limiting -------------------------------------------
# burst MUST stay at 1. Setting burst > 1 lets multiple tokens accumulate
# and fire simultaneously at window boundaries, causing ENISA 403 storms.
# To increase throughput, reduce REQUEST_SPACING (carefully) — never raise burst.
MAX_CONCURRENT_PAGES = 4      # Max pages simultaneously in-flight
REQUEST_SPACING      = 0.7    # Seconds between token-bucket grants (~1.43 req/s)
WINDOW_SIZE          = 32     # Pages per asyncio.gather() call

# --- Retry / Backoff --------------------------------------------------------
MAX_RETRIES    = 6
BACKOFF_BASE   = 4.0
BACKOFF_CAP    = 120.0
BACKOFF_JITTER = 0.4

RETRIABLE_CODES = {403, 429, 500, 502, 503, 504}

# --- State Document IDs -----------------------------------------------------
RUN_STATE_ID = "euvd_run_state"
LAST_RUN_ID  = "euvd_last_run"

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
    """
    Async token-bucket rate limiter.

    burst is always 1. Even though MAX_CONCURRENT_PAGES > 1, each concurrent
    page must wait its turn through the limiter — they share one queue.
    This prevents the thundering-herd effect where all semaphore slots fire
    simultaneously at the start of each window and trip ENISA's rate guard.
    Steady-state throughput = 1 / REQUEST_SPACING req/s.
    """

    def __init__(self, rate: float, burst: int = 1) -> None:
        self._rate   = rate
        self._burst  = float(burst)
        self._tokens = float(burst)
        self._last   = 0.0
        self._lock   = asyncio.Lock()

    async def acquire(self) -> None:
        async with self._lock:
            now          = asyncio.get_event_loop().time()
            elapsed      = now - self._last if self._last else 0.0
            self._last   = now
            self._tokens = min(self._burst, self._tokens + elapsed * self._rate)
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


def _normalize_stored_date(dt: datetime | None) -> datetime | None:
    """Normalizes a stored datetime to UTC-aware (Motor may return naive UTC)."""
    if dt and dt.tzinfo is None:
        return dt.replace(tzinfo=UTC)
    return dt

# ---------------------------------------------------------------------------
# State Management  (GRIDr / metadata)
# ---------------------------------------------------------------------------

async def _load_run_state(db) -> dict | None:
    return await db[COLL_META].find_one({"_id": RUN_STATE_ID})


async def _save_run_state(
    db,
    last_completed_page: int,
    total_pages:         int,
    run_started_at:      datetime,
    total_at_start:      int,
) -> None:
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
    await db[COLL_META].delete_one({"_id": RUN_STATE_ID})
    logger.info("Run state cleared.")


async def _load_last_run(db) -> datetime | None:
    doc = await db[COLL_META].find_one({"_id": LAST_RUN_ID})
    return doc.get("completed_at") if doc else None


async def _save_last_run(db, completed_at: datetime, stats: dict) -> None:
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
    await db[COLL_NAME].create_index("id", unique=True)
    await db[COLL_NAME].create_index("_date_updated_parsed")
    logger.info("Indexes on 'id' and '_date_updated_parsed' verified.")

# ---------------------------------------------------------------------------
# Bulk Page Processor
# ---------------------------------------------------------------------------

async def process_page(
    data:       dict[str, Any],
    source_url: str,
    db,
) -> tuple[int, int, int]:
    """
    Stores all items from one fetched page using bulk_write.

    Algorithm
    ---------
    1. Parse all items and build a {euvd_id: incoming_date} map.
    2. Bulk-fetch existing _date_updated_parsed for all IDs in one find().
    3. Determine which items are new, updated, or unchanged (in Python).
    4. Issue a single bulk_write(ReplaceOne, upsert=True) for new/updated only.

    This replaces ~200 individual round-trips (find_one + update_one per item)
    with exactly 2 DB operations regardless of page size.

    Returns (inserted, updated, skipped) counts.
    """
    items = data.get("items") or []
    if not items:
        return 0, 0, 0

    now = datetime.now(UTC)

    # --- Step 1: Parse all incoming items -----------------------------------
    # parsed_items: list of (euvd_id, incoming_date, original_item)
    parsed: list[tuple[str, datetime | None, dict]] = []
    skipped = 0

    for item in items:
        euvd_id = (item.get("id") or "").strip()
        if not euvd_id:
            logger.warning("  [SKIP] Item has no 'id' field.")
            skipped += 1
            continue
        parsed.append((euvd_id, _parse_enisa_date(item.get("dateUpdated")), item))

    if not parsed:
        return 0, 0, skipped

    all_ids = [p[0] for p in parsed]

    # --- Step 2: Bulk-fetch existing change-detection timestamps ------------
    existing_dates: dict[str, datetime | None] = {}
    cursor = db[COLL_NAME].find(
        {"id": {"$in": all_ids}},
        {"id": 1, "_date_updated_parsed": 1},
    )
    async for doc in cursor:
        existing_dates[doc["id"]] = _normalize_stored_date(
            doc.get("_date_updated_parsed")
        )

    # --- Step 3: Change detection in Python ---------------------------------
    ops: list[ReplaceOne] = []
    inserted = updated = 0

    for euvd_id, incoming_date, item in parsed:
        stored_date = existing_dates.get(euvd_id)  # None means not in DB

        if stored_date is not None:
            # Already exists — skip if not newer
            if incoming_date and stored_date and incoming_date <= stored_date:
                logger.debug(f"  [SKIP] {euvd_id} — unchanged.")
                skipped += 1
                continue
            updated += 1
        else:
            inserted += 1

        document = {
            **item,
            "mirrored_at":          now,
            "source_url":           source_url,
            "_date_updated_parsed": incoming_date,
        }
        ops.append(ReplaceOne({"id": euvd_id}, document, upsert=True))

    # --- Step 4: Single bulk_write ------------------------------------------
    if ops:
        await db[COLL_NAME].bulk_write(ops, ordered=False)

    return inserted, updated, skipped

# ---------------------------------------------------------------------------
# Delta Early-Termination Helper
# ---------------------------------------------------------------------------

def _page_is_all_old(data: dict[str, Any], since: datetime) -> bool:
    """
    Returns True if every item on the page has dateUpdated <= since.
    Used for delta early-termination.
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
                    logger.error(
                        f"  [FAILED] page {page} — HTTP {resp.status_code} "
                        f"after {MAX_RETRIES} retries."
                    )
                    return None

                logger.warning(
                    f"  [HTTP {resp.status_code}] page {page} — non-retriable, skipped."
                )
                return None

            except httpx.TimeoutException:
                if attempt < MAX_RETRIES:
                    delay = _backoff_delay(attempt)
                    logger.warning(
                        f"  [TIMEOUT] page {page} "
                        f"(attempt {attempt + 1}/{MAX_RETRIES}) — retry in {delay:.1f}s"
                    )
                    await asyncio.sleep(delay)
                else:
                    logger.error(
                        f"  [FAILED] page {page} — timed out after {MAX_RETRIES} retries."
                    )
                    return None

            except (httpx.ConnectError, httpx.RemoteProtocolError) as exc:
                if attempt < MAX_RETRIES:
                    delay = _backoff_delay(attempt)
                    logger.warning(
                        f"  [CONN ERROR] page {page}: {exc} "
                        f"(attempt {attempt + 1}/{MAX_RETRIES}) — retry in {delay:.1f}s"
                    )
                    await asyncio.sleep(delay)
                else:
                    logger.error(
                        f"  [FAILED] page {page} — connection error after "
                        f"{MAX_RETRIES} retries: {exc}"
                    )
                    return None

            except Exception as exc:
                logger.error(f"  [ERROR] page {page}: {exc}")
                return None

    return None

# ---------------------------------------------------------------------------
# Fetch-and-Process Coroutine (per page)
# ---------------------------------------------------------------------------

async def fetch_and_process_page(
    client:        httpx.AsyncClient,
    db,
    page:          int,
    semaphore:     asyncio.Semaphore,
    limiter:       RateLimiter,
    prefetched:    dict[int, dict] | None = None,
) -> tuple[int, int, int, int, bool]:
    """
    Fetches and processes a single page.

    Returns (inserted, updated, skipped, failed, data_was_fetched).
    'data_was_fetched' is False only if the HTTP fetch permanently failed,
    which lets the caller decide whether to count this page as failed.
    """
    page_url = f"{ENISA_SEARCH_URL}?size={PAGE_SIZE}&page={page}"

    # Use pre-fetched data (page 0) if available
    if prefetched and page in prefetched:
        data = prefetched[page]
    else:
        data = await fetch_page(client, page, semaphore, limiter)

    if data is None:
        return 0, 0, 0, PAGE_SIZE, False

    ins, upd, skp = await process_page(data, page_url, db)
    return ins, upd, skp, 0, True

# ---------------------------------------------------------------------------
# Entry Point
# ---------------------------------------------------------------------------

async def run_import() -> None:
    """
    Main coroutine. Determines run mode, processes pages in concurrent windows,
    checkpoints after each window, and saves last-run state on completion.

    Concurrency Model
    -----------------
    Pages are dispatched in windows of WINDOW_SIZE using asyncio.gather.
    Within each window, a shared asyncio.Semaphore(MAX_CONCURRENT_PAGES) caps
    the number of pages simultaneously performing HTTP I/O. The RateLimiter
    (token bucket, burst=MAX_CONCURRENT_PAGES) enforces the global request rate.

    Checkpoint Safety with Concurrent Pages
    ----------------------------------------
    Pages within a window may complete out of order. The checkpoint always
    records the highest *contiguous* page that has completed, starting from
    start_page. This ensures that after a crash, resume starts from a page
    that is guaranteed to need processing.
    """
    mongo_client = AsyncIOMotorClient(MONGO_URI)
    db           = mongo_client[DB_NAME]

    try:
        await ensure_indexes(db)

        semaphore = asyncio.Semaphore(MAX_CONCURRENT_PAGES)
        # burst=1: strictly one token at a time — no accumulation between windows.
        limiter   = RateLimiter(rate=1.0 / REQUEST_SPACING, burst=1)

        run_state = await _load_run_state(db)
        last_run  = await _load_last_run(db)

        async with httpx.AsyncClient(headers=HEADERS, verify=True) as client:

            # ----------------------------------------------------------------
            # Fetch page 0 — needed for total count and FULL SEED / DELTA
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
            if run_state:
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
                    logger.info(
                        f"MODE: FULL SEED — {total_entries:,} entries "
                        f"across {total_pages:,} pages"
                    )

            logger.info("=" * 60)
            logger.info(
                f"Concurrency: {MAX_CONCURRENT_PAGES} pages in-flight | "
                f"Rate: 1 req/{REQUEST_SPACING}s (~{1/REQUEST_SPACING:.1f} req/s) | "
                f"Window: {WINDOW_SIZE} pages/gather | burst=1 (strict)"
            )
            logger.info("=" * 60)

            # ----------------------------------------------------------------
            # Page loop — windowed concurrent gather
            # ----------------------------------------------------------------
            total_inserted = total_updated = total_skipped = total_failed = 0

            # highest_contiguous tracks the checkpoint watermark
            # It is the largest page N such that all pages [start_page..N] are done.
            highest_contiguous = start_page - 1

            # Pre-seed page 0 data so it isn't fetched again (only in non-RESUME modes
            # where start_page == 0)
            prefetched: dict[int, dict] = {}
            if start_page == 0 and not run_state:
                prefetched[0] = first_data

            delta_cutoff_triggered = False

            page_range = list(range(start_page, total_pages))

            for window_start in range(0, len(page_range), WINDOW_SIZE):
                if delta_cutoff_triggered:
                    break

                window_pages = page_range[window_start:window_start + WINDOW_SIZE]

                # --- DELTA pre-check for the window's first page -----------
                # For DELTA mode, quickly check page 0 (or window start) to
                # see if we can skip the entire window. The per-item safety
                # net in process_page handles boundary cases.
                if mode == "DELTA" and last_run:
                    # Check the first page of the window using prefetched or
                    # first_data if available; otherwise we defer to post-fetch.
                    first_page_in_window = window_pages[0]
                    if first_page_in_window in prefetched:
                        if _page_is_all_old(prefetched[first_page_in_window], last_run):
                            logger.info(
                                f"  [DELTA CUTOFF] page {first_page_in_window} — "
                                f"all items already up-to-date. Stopping."
                            )
                            delta_cutoff_triggered = True
                            break

                # Dispatch all pages in this window concurrently
                tasks = [
                    fetch_and_process_page(
                        client, db, p, semaphore, limiter,
                        prefetched if p in prefetched else None,
                    )
                    for p in window_pages
                ]
                window_results = await asyncio.gather(*tasks, return_exceptions=True)

                # --- Accumulate results and update watermark ----------------
                completed_in_window: set[int] = set()

                for i, result in enumerate(window_results):
                    page = window_pages[i]

                    if isinstance(result, Exception):
                        logger.error(f"  [ERROR] page {page}: {result}")
                        total_failed += PAGE_SIZE
                        # Don't mark as completed — checkpoint won't advance past it
                        continue

                    ins, upd, skp, fail, fetched = result

                    if not fetched:
                        logger.warning(
                            f"  [SKIP] page {page} could not be fetched — "
                            f"checkpoint will not advance past page {highest_contiguous}."
                        )
                        total_failed += fail
                        continue

                    # --- DELTA per-page cutoff check (post-fetch) -----------
                    # We re-use the raw data indirectly: if everything was skipped
                    # and nothing was inserted/updated, treat as a signal that
                    # the page was all-old. This is a conservative heuristic;
                    # the real cutoff is the prefetched check above.
                    # For a strict check we'd need to retain the raw data, but
                    # that trades memory for accuracy. The skipped-only heuristic
                    # is sufficient for typical DELTA runs where the API sorts
                    # newest-first.
                    if mode == "DELTA" and last_run and ins == 0 and upd == 0 and skp > 0:
                        logger.info(
                            f"  [DELTA CUTOFF] page {page} — "
                            f"all items unchanged. Stopping after this window."
                        )
                        delta_cutoff_triggered = True
                        # Still record this page as completed so checkpoint advances
                        completed_in_window.add(page)
                        total_inserted += ins
                        total_updated  += upd
                        total_skipped  += skp
                        total_failed   += fail
                        continue

                    completed_in_window.add(page)
                    total_inserted += ins
                    total_updated  += upd
                    total_skipped  += skp
                    total_failed   += fail

                # Advance contiguous watermark
                for p in window_pages:
                    if p in completed_in_window:
                        if p == highest_contiguous + 1:
                            highest_contiguous = p
                        # else: gap — watermark stays where it is
                    else:
                        break  # First gap — stop advancing

                # Checkpoint the watermark after each window
                if highest_contiguous >= start_page:
                    await _save_run_state(
                        db, highest_contiguous, total_pages,
                        run_started_at, total_at_start,
                    )

                # Progress log every window
                logger.info(
                    f"  Progress: pages {window_pages[0]}–{window_pages[-1]}/{total_pages - 1} | "
                    f"Window: +{total_inserted} ins / +{total_updated} upd / "
                    f"{total_skipped} skp | "
                    f"Checkpoint: page {highest_contiguous}"
                )

                if delta_cutoff_triggered:
                    break

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
