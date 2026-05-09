"""
join.py
=======
GRIDd Join Pipeline: Reads raw CSAF advisories from GRIDr/cert-bund,
explodes them into one document per CVE, enriches each with EUVD data,
links to GRIDd vendor/product references, and upserts into GRIDd/advisories.

Mapping rules are loaded from mapping.json at runtime.

Explosion Logic
---------------
A single CERT-BUND advisory typically covers multiple CVEs (vulnerabilities[]).
Each CVE gets its own document in GRIDd/advisories. Shared advisory fields
(title, description, OS, references) are copied to all resulting documents.

Join Logic
----------
For each CVE extracted from CERT-BUND, the pipeline searches GRIDr/euvd for a
matching document by checking whether the CVE-ID appears in the aliases field
(via regex, as per mapping.json). If found, EUVD fields are merged using the
priority defined in mapping.json (CERT-BUND primary, EUVD secondary/fallback).

Data Priority (from mapping.json)
----------------------------------
  CERT-BUND (primary):  title, description, CVSS, affected_os, remediation
  EUVD (secondary):     epss, exploitedSince, description fallback

Infrastructure Links
--------------------
Affected product IDs from vulnerabilities[].product_status.known_affected are
resolved against the CSAF product_tree to get vendor/product names, then
looked up in GRIDd/vendors and GRIDd/products to produce ObjectId references.
Results are cached per run to minimize DB round-trips.

Change Detection (Watermark)
-----------------------------
Stored in GRIDd/metadata under _id "join_processor". Only CERT-BUND documents
with mirrored_at > last_watermark are processed per run.

GRIDd/advisories Unique Key: cve_id (unique index)
If the same CVE appears in multiple CERT-BUND advisories, data is merged
(CERT-BUND source with the most recent tracking date wins for shared fields).

Fault Tolerance
---------------
  - Per-document errors are logged and skipped; the run continues.
  - Per-CVE errors within a document are logged and skipped.
  - Transient DB errors retry with exponential backoff.
  - Watermark only advances after a fully successful batch.
"""

import asyncio
import json
import logging
import re
from datetime import datetime, UTC
from pathlib import Path
from typing import Any

from motor.motor_asyncio import AsyncIOMotorClient
from pymongo.errors import PyMongoError

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

CONFIG_DIR          = Path(__file__).parent.parent
MAPPING_CONFIG_PATH = CONFIG_DIR / "mapping.json"
VENDORS_CONFIG_PATH = CONFIG_DIR / "vendors.json"

MONGO_URI = "mongodb://localhost:27017/"
GRIDR_DB  = "GRIDr"
GRIDD_DB  = "GRIDd"

COLL_CERT_BUND = "cert-bund"
COLL_EUVD      = "euvd"
COLL_ADVISORIES = "advisories"
COLL_VENDORS    = "vendors"
COLL_PRODUCTS   = "products"
COLL_META       = "metadata"

PROCESSOR_STATE_ID = "join_processor"
BATCH_SIZE         = 100
MAX_DB_RETRIES     = 3
RETRY_DELAY        = 2.0

# CSAF remediation category → human-readable status
REMEDIATION_STATUS_MAP = {
    "vendor_fix":      "Patch available",
    "mitigation":      "Mitigation available",
    "workaround":      "Workaround available",
    "no_fix_planned":  "No fix planned",
    "none_available":  "No fix available",
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
# Config Loader
# ---------------------------------------------------------------------------

def load_configs() -> tuple[dict, dict]:
    """Loads mapping.json and vendors.json. Raises on missing/malformed files."""
    for path in (MAPPING_CONFIG_PATH, VENDORS_CONFIG_PATH):
        if not path.exists():
            raise FileNotFoundError(f"Config not found: {path}")
    with open(MAPPING_CONFIG_PATH, encoding="utf-8") as f:
        mapping = json.load(f)
    with open(VENDORS_CONFIG_PATH, encoding="utf-8") as f:
        vendors_cfg = json.load(f)
    logger.info(f"Loaded mapping.json v{mapping['mapping_definition'].get('version', '?')}")
    return mapping, vendors_cfg

# ---------------------------------------------------------------------------
# Normalization (mirrors vendors.py / products.py)
# ---------------------------------------------------------------------------

def normalize_vendor_name(raw: str, vendors_cfg: dict) -> str:
    norm = vendors_cfg["normalization"]
    name = raw.strip()
    for suffix in sorted(norm["strip_suffixes"], key=len, reverse=True):
        if name.endswith(suffix):
            name = name[: -len(suffix)].strip()
            break
    if norm["formatting"].get("case_handling") == "proper_case":
        name = name.title()
    return name.strip() or raw.strip()


def normalize_product_name(raw: str, normalized_vendor: str) -> str:
    name = raw.strip()
    prefix = normalized_vendor + " "
    if name.lower().startswith(prefix.lower()):
        name = name[len(prefix):].strip()
    name = re.sub(r"\s+", " ", name).strip().title()
    return name or raw.strip()

# ---------------------------------------------------------------------------
# CSAF Field Extractors
# ---------------------------------------------------------------------------

def _notes_field(notes: list[dict], category: str, field: str = "text") -> str:
    """Returns the first matching note field by category."""
    for note in notes:
        if note.get("category") == category:
            return (note.get(field) or "").strip()
    return ""


def extract_summary(csaf_doc: dict) -> str:
    notes = csaf_doc.get("document", {}).get("notes", [])
    return _notes_field(notes, "summary")


def extract_affected_os(csaf_doc: dict) -> list[str]:
    """Parses 'general' note into a list of OS strings."""
    notes = csaf_doc.get("document", {}).get("notes", [])
    raw   = _notes_field(notes, "general")
    if not raw:
        return []
    # Lines like "- Linux\n- UNIX" → ["Linux", "UNIX"]
    return [
        line.lstrip("- ").strip()
        for line in raw.splitlines()
        if line.strip().lstrip("- ").strip()
    ]


def extract_references(csaf_doc: dict) -> list[str]:
    """Returns external reference URLs from document.references[]."""
    refs = csaf_doc.get("document", {}).get("references", [])
    return [
        r["url"] for r in refs
        if r.get("category") == "external" and r.get("url")
    ]


def extract_self_references(csaf_doc: dict) -> list[str]:
    """Returns self-reference URLs (CSAF + portal links)."""
    refs = csaf_doc.get("document", {}).get("references", [])
    return [r["url"] for r in refs if r.get("category") == "self" and r.get("url")]


def extract_cvss(vuln: dict) -> dict | None:
    """
    Extracts the first available CVSS v3 score from a vulnerability entry.
    Returns a dict with base_score, vector, version or None.
    """
    for score_entry in vuln.get("scores", []):
        cvss = score_entry.get("cvss_v3") or score_entry.get("cvssV3", {})
        if cvss:
            return {
                "base_score": cvss.get("baseScore"),
                "vector":     cvss.get("vectorString"),
                "version":    cvss.get("version"),
            }
    return None


def extract_exploitation_status(vuln: dict) -> str | None:
    """Returns the details of the first exploit_status threat entry."""
    for threat in vuln.get("threats", []):
        if threat.get("category") == "exploit_status":
            return (threat.get("details") or "").strip() or None
    return None


def extract_remediation(vuln: dict, pid_to_version: dict) -> dict:
    """
    Extracts remediation info from a vulnerability.

    Two data sources (in order of priority):
    1. vuln.remediations[] — explicit remediation entries (not always present in CERT-BUND)
    2. CERT-BUND implicit convention: for each affected product_id (e.g. "T053720"),
       the corresponding fixed product is stored in the product_tree under the key
       "{pid}-fixed" (e.g. "T053720-fixed"). This key is never in product_status itself
       — it must be derived and looked up in pid_to_version (the product_tree map).
    """
    remediations = vuln.get("remediations", [])
    status  = None
    details = None

    if remediations:
        rem = remediations[0]
        status  = REMEDIATION_STATUS_MAP.get(rem.get("category", ""), rem.get("category"))
        details = (rem.get("details") or "").strip() or None

    fixed_versions: list[str] = []
    product_status = vuln.get("product_status", {})

    for status_key, pids in product_status.items():
        for pid in (pids or []):
            # Strategy 1: explicit "fixed" status key in product_status
            if status_key == "fixed":
                ver = pid_to_version.get(pid, {}).get("version_string")
                if ver and ver not in fixed_versions:
                    fixed_versions.append(ver)

            # Strategy 2: CERT-BUND implicit convention
            # Affected PID "T053720" → fixed PID "T053720-fixed" in product_tree
            derived_fixed_pid = f"{pid}-fixed"
            info = pid_to_version.get(derived_fixed_pid)
            if info:
                ver = info.get("version_string")
                if ver and ver not in fixed_versions:
                    fixed_versions.append(ver)

            # Strategy 3: the pid itself already ends in "-fixed"
            # (edge case, some CSAF producers list fixed pids in known_affected)
            if pid.endswith("-fixed"):
                ver = pid_to_version.get(pid, {}).get("version_string")
                if ver and ver not in fixed_versions:
                    fixed_versions.append(ver)

    if fixed_versions and not status:
        status = "Patch available"

    return {
        "status":         status,
        "details":        details,
        "fixed_versions": fixed_versions,
    }


# ---------------------------------------------------------------------------
# Version Extraction (all affected/fixed entries)
# ---------------------------------------------------------------------------

_VERSION_RANGE_RE = re.compile(r"[<>]=?|<<")

# Maps CSAF product_status keys → human-readable status label stored in GRIDd
PRODUCT_STATUS_LABELS: dict[str, str] = {
    "known_affected":      "affected",
    "first_affected":      "affected",
    "last_affected":       "last_affected",
    "known_not_affected":  "not_affected",
    "first_fixed":         "fixed",
    "fixed":               "fixed",
    "recommended":         "fixed",
    "under_investigation": "under_investigation",
}


def extract_all_versions(
    vuln:     dict,
    pid_map:  dict,
    euvd_doc: dict | None,
) -> list[dict]:
    """
    Builds a unified list of ALL version entries for this CVE, across sources.

    Sources
    -------
    1. CSAF product_status keys (known_affected, last_affected, fixed, …)
       resolved to version strings via pid_map (built from product_tree).
    2. CERT-BUND implicit fix convention:
       affected PID "T053720" → companion fixed PID "T053720-fixed" in product_tree.
    3. EUVD enisaIdProduct[].product_version (supplemental, source='euvd').

    Entry Schema
    ------------
      {
        vendor:   str,   # e.g. "Apache"
        product:  str,   # e.g. "CloudStack"
        version:  str,   # e.g. "LTS <4.20.3.0"
        is_range: bool,  # True if version string contains <, >, <=, >=
        status:   str,   # "affected" | "fixed" | "last_affected" | ...
        cpe:      str,   # CPE identifier or "" if unavailable
        source:   str,   # "csaf" | "euvd"
      }
    """
    entries: list[dict] = []
    seen:    set[tuple] = set()   # (vendor, product, version, status) dedup

    def _add(
        vendor: str, product: str, version: str,
        status: str, cpe: str, source: str = "csaf",
    ) -> None:
        version = (version or "").strip()
        if not version or not product:
            return
        key = (vendor, product, version, status)
        if key in seen:
            return
        seen.add(key)
        entries.append({
            "vendor":   vendor,
            "product":  product,
            "version":  version,
            "is_range": bool(_VERSION_RANGE_RE.search(version)),
            "status":   status,
            "cpe":      cpe or "",
            "source":   source,
        })

    # --- CSAF product_status entries ---
    product_status = vuln.get("product_status", {})
    for status_key, pids in product_status.items():
        label = PRODUCT_STATUS_LABELS.get(status_key, status_key)
        for pid in (pids or []):
            info = pid_map.get(pid)
            if not info:
                continue
            _add(
                info["vendor_name"], info["product_name"],
                info["version_string"], label, info["cpe"],
            )
            # CERT-BUND implicit fix: affected PID → companion "{pid}-fixed"
            if label == "affected":
                fixed_info = pid_map.get(f"{pid}-fixed")
                if fixed_info:
                    _add(
                        fixed_info["vendor_name"], fixed_info["product_name"],
                        fixed_info["version_string"], "fixed", fixed_info["cpe"],
                    )

    # --- EUVD product versions (supplemental) ---
    if euvd_doc:
        vendor_map: dict[str, str] = {
            e.get("id", ""): ((e.get("vendor") or {}).get("name") or "")
            for e in euvd_doc.get("enisaIdVendor", [])
        }
        for prod_entry in euvd_doc.get("enisaIdProduct", []):
            pid     = prod_entry.get("id", "")
            pname   = ((prod_entry.get("product") or {}).get("name") or "").strip()
            ver_str = (prod_entry.get("product_version") or "").strip()
            vname   = vendor_map.get(pid, "")
            if pname and ver_str:
                _add(vname, pname, ver_str, "affected", "", "euvd")

    return entries


def build_product_id_map(csaf_doc: dict) -> dict[str, dict]:
    """
    Recursively walks product_tree and builds:
      product_id → { vendor_name, product_name, version_string, cpe }
    """
    pid_map: dict[str, dict] = {}

    def walk(branches: list, vendor: str = "", product: str = "") -> None:
        for branch in branches:
            cat  = branch.get("category", "")
            name = branch.get("name", "")
            cur_vendor  = name if cat == "vendor"       else vendor
            cur_product = name if cat == "product_name" else product

            prod_obj = branch.get("product") or {}
            pid      = prod_obj.get("product_id")
            if pid:
                cpe = (prod_obj.get("product_identification_helper") or {}).get("cpe", "")
                pid_map[pid] = {
                    "vendor_name":     cur_vendor,
                    "product_name":    cur_product,
                    "version_string":  name,
                    "cpe":             cpe,
                }
            walk(branch.get("branches", []), cur_vendor, cur_product)

    walk(csaf_doc.get("product_tree", {}).get("branches", []))
    return pid_map

# ---------------------------------------------------------------------------
# EUVD Helpers
# ---------------------------------------------------------------------------

CVE_PATTERN = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)


def parse_euvd_references(raw: str) -> list[str]:
    """Splits a newline-separated EUVD reference string into a URL list."""
    return [u.strip() for u in raw.split("\n") if u.strip().startswith("http")]

# ---------------------------------------------------------------------------
# DB Helpers
# ---------------------------------------------------------------------------

async def _retry(coro_fn, retries: int = MAX_DB_RETRIES, delay: float = RETRY_DELAY):
    last_exc: Exception | None = None
    for attempt in range(retries + 1):
        try:
            return await coro_fn()
        except PyMongoError as exc:
            last_exc = exc
            if attempt < retries:
                logger.warning(f"  [DB RETRY] {exc} ({attempt + 1}/{retries})")
                await asyncio.sleep(delay * (2 ** attempt))
    raise last_exc


async def load_watermark(db_gridd) -> datetime:
    doc = await db_gridd[COLL_META].find_one({"_id": PROCESSOR_STATE_ID})
    if doc and doc.get("last_watermark"):
        wm = doc["last_watermark"]
        return wm.replace(tzinfo=UTC) if wm.tzinfo is None else wm
    return datetime.min.replace(tzinfo=UTC)


async def save_watermark(db_gridd, watermark: datetime, stats: dict) -> None:
    await db_gridd[COLL_META].update_one(
        {"_id": PROCESSOR_STATE_ID},
        {"$set": {"last_watermark": watermark, "updated_at": datetime.now(UTC), **stats}},
        upsert=True,
    )
    logger.info(f"Watermark advanced to {watermark.isoformat()}")


async def ensure_indexes(db_gridd) -> None:
    await db_gridd[COLL_ADVISORIES].create_index("cve_id", unique=True)
    await db_gridd[COLL_ADVISORIES].create_index("metadata.raw_source_ids.cert_bund")
    await db_gridd[COLL_ADVISORIES].create_index("infrastructure.links.vendor_id")
    await db_gridd[COLL_ADVISORIES].create_index("infrastructure.links.product_id")
    logger.info("Indexes on GRIDd/advisories verified.")

# ---------------------------------------------------------------------------
# GRIDd Lookup Cache
# ---------------------------------------------------------------------------

class GRIDdCache:
    """
    In-memory cache for GRIDd vendor/product lookups within a single run.
    Avoids repeated DB round-trips for the same normalized names.
    """

    def __init__(self) -> None:
        self._vendors:  dict[str, Any] = {}  # normalized_name → _id | None
        self._products: dict[tuple, Any] = {}  # (vendor_name, product_name) → _id | None

    async def get_vendor_id(self, db_gridd, normalized_name: str) -> Any:
        if normalized_name not in self._vendors:
            doc = await db_gridd[COLL_VENDORS].find_one(
                {"name": normalized_name}, {"_id": 1}
            )
            self._vendors[normalized_name] = doc["_id"] if doc else None
        return self._vendors[normalized_name]

    async def get_product_id(self, db_gridd, vendor_name: str, product_name: str) -> Any:
        key = (vendor_name, product_name)
        if key not in self._products:
            doc = await db_gridd[COLL_PRODUCTS].find_one(
                {"vendor_name": vendor_name, "name": product_name}, {"_id": 1}
            )
            self._products[key] = doc["_id"] if doc else None
        return self._products[key]

# ---------------------------------------------------------------------------
# Core: Advisory Builder
# ---------------------------------------------------------------------------

async def build_advisory(
    cve_id:    str,
    vuln:      dict,
    csaf_doc:  dict,
    pid_map:   dict,
    euvd_doc:  dict | None,
    db_gridd,
    cache:     GRIDdCache,
    vendors_cfg: dict,
) -> dict:
    """
    Constructs a single GRIDd/advisories document for one CVE.

    Data Priority: CERT-BUND (primary) → EUVD (secondary/fallback).
    """
    doc_meta  = csaf_doc.get("document", {})
    tracking  = doc_meta.get("tracking", {})
    now       = datetime.now(UTC)

    # --- CVSS (CERT-BUND primary, EUVD fallback) ---
    cvss_data = extract_cvss(vuln)
    cvss_v3: dict | None = None
    if cvss_data and cvss_data.get("base_score") is not None:
        cvss_v3 = cvss_data
    elif euvd_doc:
        score = euvd_doc.get("baseScore")
        if score is not None:
            cvss_v3 = {
                "base_score": score,
                "vector":     euvd_doc.get("baseScoreVector"),
                "version":    euvd_doc.get("baseScoreVersion"),
            }

    # --- Exploitation status (CERT-BUND primary, EUVD fallback) ---
    exploitation = extract_exploitation_status(vuln)
    if not exploitation and euvd_doc:
        since = euvd_doc.get("exploitedSince")
        if since:
            exploitation = f"Exploited since {since}"

    # --- Description (CERT-BUND primary, EUVD fallback) ---
    description = extract_summary(csaf_doc)
    if not description and euvd_doc:
        description = (euvd_doc.get("description") or "").strip()

    # --- References (merge both sources, deduplicated) ---
    ref_set: set[str] = set()
    ref_set.update(extract_self_references(csaf_doc))
    ref_set.update(extract_references(csaf_doc))
    if euvd_doc:
        ref_set.update(parse_euvd_references(euvd_doc.get("references", "")))
    references = sorted(ref_set)

    # --- Affected OS ---
    affected_os = extract_affected_os(csaf_doc)

    # --- All version entries (affected + fixed, from CSAF product_tree + EUVD) ---
    all_versions = extract_all_versions(vuln, pid_map, euvd_doc)

    # --- Remediation (status/details from remediations[]; fixed list from all_versions) ---
    remediation = extract_remediation(vuln, pid_map)
    # Override fixed_versions with the richer all_versions data
    derived_fixed = [v["version"] for v in all_versions if v["status"] == "fixed"]
    if derived_fixed:
        remediation["fixed_versions"] = derived_fixed

    # --- Infrastructure links ---
    known_affected = vuln.get("product_status", {}).get("known_affected", []) or []
    links: list[dict] = []
    seen_pairs: set[tuple] = set()

    for pid in known_affected:
        info = pid_map.get(pid)
        if not info:
            continue
        raw_vendor  = info["vendor_name"]
        raw_product = info["product_name"]
        if not raw_vendor or not raw_product:
            continue

        norm_vendor  = normalize_vendor_name(raw_vendor, vendors_cfg)
        norm_product = normalize_product_name(raw_product, norm_vendor)
        pair = (norm_vendor, norm_product)
        if pair in seen_pairs:
            continue
        seen_pairs.add(pair)

        vendor_id  = await cache.get_vendor_id(db_gridd, norm_vendor)
        product_id = await cache.get_product_id(db_gridd, norm_vendor, norm_product)

        if vendor_id or product_id:
            links.append({
                "vendor_id":  vendor_id,
                "product_id": product_id,
            })
        else:
            logger.debug(
                f"  [LINK MISS] Vendor={norm_vendor!r} Product={norm_product!r} "
                f"not found in GRIDd — run vendors.py and products.py first."
            )

    # --- Timeline ---
    pub_raw = tracking.get("initial_release_date") or ""
    mod_raw = tracking.get("current_release_date") or ""

    def _parse_iso(s: str) -> str | None:
        """Returns ISO string or None."""
        return s.replace("Z", "+00:00") if s else None

    # --- Sources metadata ---
    sources      = ["csaf"]
    raw_src_ids  = {"cert_bund": tracking.get("id")}
    if euvd_doc:
        sources.append("euvd")
        raw_src_ids["euvd"] = euvd_doc.get("id")

    # --- EPSS (EUVD only) ---
    epss = euvd_doc.get("epss") if euvd_doc else None

    return {
        "cve_id":      cve_id,
        "title":       doc_meta.get("title", ""),
        "description": description,
        "metrics": {
            "cvss_v3":            cvss_v3,
            "epss":               epss,
            "exploitation_status": exploitation,
        },
        "infrastructure": {
            "affected_os":       affected_os,
            "affected_versions": all_versions,
            "links":             links,
        },
        "remediation": remediation,
        "timeline": {
            "published_at": _parse_iso(pub_raw),
            "modified_at":  _parse_iso(mod_raw),
        },
        "intel": {
            "references": references,
        },
        "metadata": {
            "sources":        sources,
            "raw_source_ids": raw_src_ids,
            "last_processed": now,
        },
    }

# ---------------------------------------------------------------------------
# EUVD Lookup
# ---------------------------------------------------------------------------

async def lookup_euvd(db_gridr, cve_id: str) -> dict | None:
    """
    Searches GRIDr/euvd for a document whose aliases field contains the CVE-ID.
    Uses a regex query as defined in mapping.json.
    """
    try:
        return await db_gridr[COLL_EUVD].find_one(
            {"aliases": {"$regex": re.escape(cve_id), "$options": "i"}},
        )
    except PyMongoError as exc:
        logger.warning(f"  [EUVD LOOKUP FAILED] {cve_id}: {exc}")
        return None

# ---------------------------------------------------------------------------
# Main Processing Loop
# ---------------------------------------------------------------------------

async def process_csaf_document(
    csaf_doc:    dict,
    db_gridr,
    db_gridd,
    cache:       GRIDdCache,
    vendors_cfg: dict,
) -> int:
    """
    Processes one CERT-BUND advisory: iterates over vulnerabilities[],
    joins each CVE with EUVD, builds an advisory document, and upserts it.

    Returns the number of CVE documents successfully upserted.
    """
    pid_map     = build_product_id_map(csaf_doc)
    vulns       = csaf_doc.get("vulnerabilities", [])
    upserted    = 0

    for vuln in vulns:
        cve_id = (vuln.get("cve") or "").strip()
        if not cve_id:
            continue

        try:
            euvd_doc = await lookup_euvd(db_gridr, cve_id)

            advisory = await build_advisory(
                cve_id=cve_id,
                vuln=vuln,
                csaf_doc=csaf_doc,
                pid_map=pid_map,
                euvd_doc=euvd_doc,
                db_gridd=db_gridd,
                cache=cache,
                vendors_cfg=vendors_cfg,
            )

            await _retry(lambda a=advisory: db_gridd[COLL_ADVISORIES].update_one(
                {"cve_id": a["cve_id"]},
                {"$set": a},
                upsert=True,
            ))

            euvd_tag = f" + EUVD:{euvd_doc['id']}" if euvd_doc else ""
            logger.info(f"  [UPSERT] {cve_id}{euvd_tag}")
            upserted += 1

        except Exception as exc:
            logger.error(f"  [ERROR] CVE {cve_id} in doc {csaf_doc.get('_id')}: {exc}")

    return upserted


async def run() -> None:
    """
    Main coroutine.

    Steps
    -----
    1. Load mapping.json and vendors.json configs.
    2. Connect to GRIDr and GRIDd, ensure indexes.
    3. Load the current watermark from GRIDd/metadata.
    4. Iterate over GRIDr/cert-bund documents newer than watermark.
    5. For each document: explode into per-CVE advisories, join EUVD, upsert.
    6. Advance watermark to highest mirrored_at in the batch.
    """
    mapping_cfg, vendors_cfg = load_configs()

    mongo_client = AsyncIOMotorClient(MONGO_URI)
    db_gridr     = mongo_client[GRIDR_DB]
    db_gridd     = mongo_client[GRIDD_DB]

    try:
        await ensure_indexes(db_gridd)

        watermark = await load_watermark(db_gridd)
        logger.info("=" * 60)
        logger.info(f"JOIN PIPELINE STARTED — watermark: {watermark.isoformat()}")
        logger.info("=" * 60)

        cache            = GRIDdCache()
        docs_processed   = 0
        advisories_total = 0
        new_watermark: datetime | None = None

        query  = {"mirrored_at": {"$gt": watermark}}
        cursor = db_gridr[COLL_CERT_BUND].find(query).batch_size(BATCH_SIZE)

        async for csaf_doc in cursor:
            try:
                mirrored = csaf_doc.get("mirrored_at")
                if mirrored and mirrored.tzinfo is None:
                    mirrored = mirrored.replace(tzinfo=UTC)
                if mirrored and (new_watermark is None or mirrored > new_watermark):
                    new_watermark = mirrored

                tracking_id = (
                    csaf_doc.get("document", {}).get("tracking", {}).get("id", "?")
                )
                logger.info(f"Processing {tracking_id} ({len(csaf_doc.get('vulnerabilities', []))} CVEs)...")

                n = await process_csaf_document(
                    csaf_doc, db_gridr, db_gridd, cache, vendors_cfg
                )
                advisories_total += n
                docs_processed   += 1

            except Exception as exc:
                logger.error(f"  [ERROR] Document {csaf_doc.get('_id')}: {exc}")

        if new_watermark:
            await save_watermark(db_gridd, new_watermark, {
                "last_docs_processed":   docs_processed,
                "last_advisories_upserted": advisories_total,
            })
        else:
            logger.info("No new documents found — watermark unchanged.")

        logger.info("=" * 60)
        logger.info(
            f"JOIN PIPELINE COMPLETE — "
            f"{docs_processed} CSAF docs processed, "
            f"{advisories_total} CVE advisories upserted into GRIDd."
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
