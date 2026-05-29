# GRID API v2 — Dokumentation

Asynchrone REST-API auf Basis von **FastAPI 2.0**, die verarbeitete Schwachstellendaten aus der **GRIDd**-MongoDB-Datenbank bereitstellt. Alle Antworten sind JSON.

### v2.0 — Änderungen gegenüber v1

- Alle List-Endpunkte nutzen eine **einzelne `$facet`-Aggregation** (Count + Daten in einem Round-Trip).
- Volltextsuche über gewichtete **MongoDB Text-Indexes** — kein unindexierter Regex-Scan mehr.
- Alle Filterfelder sind durch **dedizierte MongoDB-Indexes** abgesichert (werden beim Start erzeugt).
- `/API/status` wird **60 Sekunden gecacht** (TTLCache).
- **Fuzzy Search** über `rapidfuzz` für Tippfehler-tolerante Advisory-Suche.
- Neue Filter: `published_after/before`, `modified_after/before`, `min_epss/max_epss`, `has_fix`, `severity`, `exploitation_status`, `cve_ids`, `fuzzy`.
- **Sort-Allow-Lists**: `sort_by` akzeptiert nur validierte Felder (verhindert willkürliches Field-Traversal).
- List-Projections optimiert: Vendors ohne `raw_names`, Products ohne `versions`.
- Lizenz: **GPL-3.0**.

---

## Abhängigkeiten

```
fastapi[standard]>=0.111.0
motor>=3.4.0
pydantic>=2.0.0
rapidfuzz>=3.0.0
uvicorn[standard]>=0.29.0
```

## Starten

```bash
cd GRID/

# Abhängigkeiten installieren (einmalig)
pip install -r API/requirements.txt

# Entwicklungsserver
uvicorn API.main:app --reload --host 0.0.0.0 --port 8000
```

| Interface | URL |
|---|---|
| **Swagger UI** | http://localhost:8000/API/docs |
| **ReDoc** | http://localhost:8000/API/redoc |
| **OpenAPI JSON** | http://localhost:8000/API/openapi.json |

---

## Dateistruktur

```
GRID/API/
├── __init__.py
├── main.py              ← FastAPI-App, Lifespan, Index-Init, TTL-Cache, /API/status
├── database.py          ← AsyncIOMotorClient, Collection-Accessors, ensure_indexes()
├── models.py            ← Pydantic-Modelle (Advisory, Product, Vendor, IngestStatus)
├── utils.py             ← ObjectId-Konverter, Pagination, TTLCache, Sort-Allow-Lists
├── requirements.txt     ← Python-Abhängigkeiten
└── routers/
    ├── __init__.py
    ├── advisories.py    ← GET /API/advisories/, /{cve_id}, /id/{oid}
    ├── products.py      ← GET /API/products/, /{oid}
    └── vendors.py       ← GET /API/vendors/, /{oid}
```

---

## Architektur-Details

### Startup-Lifecycle

```
connect_db()  →  ensure_indexes()  →  App ready
                      ↓
      Alle Text- und Feld-Indexes
      werden idempotent erstellt
```

### MongoDB-Index-Übersicht

| Collection | Index | Typ | Zweck |
|---|---|---|---|
| advisories | `adv_text` | Text (gewichtet) | Volltextsuche: `cve_id` (×10) > `title` (×5) > `description` (×1) |
| advisories | `adv_cvss` | Ascending, sparse | CVSS-Score-Range-Filter |
| advisories | `adv_epss` | Ascending, sparse | EPSS-Score-Range-Filter |
| advisories | `adv_published_desc` | Descending | Sortierung nach Veröffentlichungsdatum |
| advisories | `adv_modified_desc` | Descending | Sortierung nach Aktualisierungsdatum |
| advisories | `adv_cvss_date` | Compound | Dashboard-Query: hoher CVSS + aktuell |
| advisories | `adv_sources` | Single-field | Source-Filter (`csaf`/`euvd`) |
| advisories | `adv_vendor` | Single-field | Vendor-Substring-Filter |
| advisories | `adv_product` | Single-field | Product-Substring-Filter |
| advisories | `adv_os` | Single-field | Betroffenes OS |
| advisories | `adv_remediation_status` | Single-field | Remediation-Status-Filter |
| advisories | `adv_severity` | Single-field, sparse | Severity-Text-Filter |
| advisories | `adv_exploit` | Single-field, sparse | Exploitation-Status-Filter |
| products | `prod_text` | Text (gewichtet) | Volltextsuche: `name` (×5) > `vendor_name` (×3) > `raw_names` (×1) |
| products | `prod_vendor` | Single-field | Vendor-Name-Filter |
| products | `prod_sources` | Single-field | Source-Filter |
| vendors | `vend_text` | Text (gewichtet) | Volltextsuche: `name` (×10) > `raw_names` (×1) |
| vendors | `vend_name` | Single-field | Name-Filter |
| vendors | `vend_sources` | Single-field | Source-Filter |

### Connection-Pool (Motor)

| Parameter | Wert | Beschreibung |
|---|---|---|
| `maxPoolSize` | 20 | Maximale gleichzeitige Verbindungen |
| `minPoolSize` | 5 | Warm gehaltene Verbindungen |
| `serverSelectionTimeoutMS` | 5.000 | Timeout für Server-Auswahl |
| `connectTimeoutMS` | 5.000 | Timeout für Verbindungsaufbau |
| `socketTimeoutMS` | 30.000 | Timeout für Socket-Operationen |

### TTLCache

`/API/status` nutzt einen in-memory TTL-Cache (60s). Nach dem ersten Request werden die Collection-Counts für 60 Sekunden gecacht, um MongoDB auf High-Traffic-Dashboards nicht zu belasten.

### Aggregation Pipeline

Alle List-Endpunkte nutzen eine `$facet`-Aggregation statt getrennter `count_documents()` + `find()`:

```
$match → [$addFields (text score)] → $facet {
    meta:  [$count],
    items: [$sort → $skip → $limit → $project]
}
```

---

## Endpunkte

### Status

| Methode | Pfad | Beschreibung |
|---|---|---|
| `GET` | `/API/status` | Collection-Counts + letzter Ingest-Datensatz (gecacht: 60s) |

**Response-Schema:**
```json
{
  "advisory_count": 3482,
  "product_count":  1204,
  "vendor_count":   187,
  "last_ingest":    { "...": "..." }
}
```

---

### Advisories (`GRIDd/advisories`)

| Methode | Pfad | Beschreibung |
|---|---|---|
| `GET` | `/API/advisories/` | Paginierte Liste mit Filtern, Suche und Fuzzy-Modus |
| `GET` | `/API/advisories/{cve_id}` | Advisory by CVE-ID (exakt, z. B. `CVE-2026-12345`) |
| `GET` | `/API/advisories/id/{object_id}` | Advisory by MongoDB ObjectId |

**Query-Parameter für `GET /API/advisories/`:**

| Parameter | Typ | Default | Beschreibung |
|---|---|---|---|
| `page` | int | `1` | Seite (1-basiert) |
| `page_size` | int | `25` | Einträge pro Seite (max. 200) |
| **Score-Filter** | | | |
| `min_cvss` | float | — | CVSS-Score ≥ Wert (0.0–10.0) |
| `max_cvss` | float | — | CVSS-Score ≤ Wert (0.0–10.0) |
| `min_epss` | float | — | EPSS-Probability ≥ Wert (0.0–1.0) |
| `max_epss` | float | — | EPSS-Probability ≤ Wert (0.0–1.0) |
| **Entity-Filter** | | | |
| `vendor_name` | string | — | Substring-Match auf `affected_versions.vendor` (case-insensitive) |
| `product_name` | string | — | Substring-Match auf `affected_versions.product` (case-insensitive) |
| `source` | string | — | Ingest-Quelle: `csaf` oder `euvd` |
| `affected_os` | string | — | Substring-Match auf `infrastructure.affected_os` |
| **Remediation / Severity** | | | |
| `remediation_status` | string | — | Substring-Match auf `remediation.status` |
| `has_fix` | bool | — | `true` = hat `fixed_versions`, `false` = keine |
| `severity` | string | — | Substring-Match auf `metrics.severity_text` (z. B. `kritisch`) |
| `exploitation_status` | string | — | Substring-Match auf `metrics.exploitation_status` |
| **Datumsbereich** | | | |
| `published_after` | datetime | — | Veröffentlicht ab (ISO-8601) |
| `published_before` | datetime | — | Veröffentlicht bis (ISO-8601) |
| `modified_after` | datetime | — | Geändert ab (ISO-8601) |
| `modified_before` | datetime | — | Geändert bis (ISO-8601) |
| **Suche** | | | |
| `search` | string | — | Volltextsuche über `cve_id`, `title`, `description` (gewichteter Text-Index) |
| `fuzzy` | bool | `false` | Fuzzy-Re-Ranking mit `rapidfuzz` (benötigt `search`) |
| `cve_ids` | string | — | Komma-getrennte CVE-IDs für Bulk-Lookup |
| **Sortierung** | | | |
| `sort_by` | string | `timeline.published_at` | Erlaubte Felder: `timeline.published_at`, `timeline.modified_at`, `metrics.cvss_v3.base_score`, `metrics.epss`, `cve_id`, `title`. Prefix `-` für Descending. Mit `search`: `relevance` für Text-Score-Ranking |

**Fuzzy-Modus:**
- Benötigt `search`; benötigt `rapidfuzz` auf dem Server
- Holt bis zu 500 Kandidaten aus MongoDB, re-rankt sie in Python
- Minimaler Fuzzy-Score: 40/100
- Deep Pagination ist im Fuzzy-Modus approximativ

---

### Products (`GRIDd/products`)

| Methode | Pfad | Beschreibung |
|---|---|---|
| `GET` | `/API/products/` | Paginierte Liste (ohne `versions`-Array) |
| `GET` | `/API/products/{object_id}` | Vollständiges Produkt inkl. `versions`-Array |

**Query-Parameter für `GET /API/products/`:**

| Parameter | Typ | Default | Beschreibung |
|---|---|---|---|
| `page` / `page_size` | int | `1` / `25` | Pagination (max. 200) |
| `vendor_name` | string | — | Substring-Match auf `vendor_name` |
| `product_name` | string | — | Substring-Match auf `name` |
| `source` | string | — | `csaf` oder `euvd` |
| `updated_after` | datetime | — | Produkte aktualisiert ab (ISO-8601) |
| `updated_before` | datetime | — | Produkte aktualisiert bis (ISO-8601) |
| `search` | string | — | Volltextsuche über `name`, `vendor_name`, `raw_names` (gewichteter Text-Index) |
| `sort_by` | string | `name` | Erlaubte Felder: `name`, `vendor_name`, `created_at`, `updated_at`. Prefix `-` für Descending |

> **Hinweis:** Die Liste gibt `versions` absichtlich nicht zurück (Performance). Für das komplette `versions`-Array: `GET /API/products/{id}`.

---

### Vendors (`GRIDd/vendors`)

| Methode | Pfad | Beschreibung |
|---|---|---|
| `GET` | `/API/vendors/` | Paginierte Liste (ohne `raw_names`) |
| `GET` | `/API/vendors/{object_id}` | Vollständiger Vendor inkl. `raw_names` |

**Query-Parameter für `GET /API/vendors/`:**

| Parameter | Typ | Default | Beschreibung |
|---|---|---|---|
| `page` / `page_size` | int | `1` / `25` | Pagination (max. 200) |
| `vendor_name` | string | — | Substring-Match auf `name` |
| `source` | string | — | `csaf` oder `euvd` |
| `search` | string | — | Volltextsuche über `name`, `raw_names` (gewichteter Text-Index) |
| `sort_by` | string | `name` | Erlaubte Felder: `name`, `created_at`, `updated_at`. Prefix `-` für Descending |

> **Hinweis:** Die Liste gibt `raw_names` absichtlich nicht zurück (Performance). Für das komplette Dokument: `GET /API/vendors/{id}`.

---

## Pagination

Alle List-Endpunkte geben ein einheitliches Pagination-Objekt zurück:

```json
{
  "data": [ "..." ],
  "pagination": {
    "total":       3482,
    "page":        1,
    "page_size":   25,
    "total_pages": 140,
    "has_next":    true,
    "has_prev":    false
  }
}
```

---

## curl-Beispiele

### 1 · API-Status

```bash
curl -s http://localhost:8000/API/status | jq .
```

### 2 · Advisory by CVE-ID

```bash
curl -s "http://localhost:8000/API/advisories/CVE-2025-66170" | jq '{
  cve_id,
  title,
  score: .metrics.cvss_v3.base_score,
  remediation: .remediation.status,
  fixed: .remediation.fixed_versions
}'
```

### 3 · Hochkritische Advisories (CVSS ≥ 9.0) für Apache

```bash
curl -s "http://localhost:8000/API/advisories/?min_cvss=9.0&vendor_name=Apache&page_size=10&sort_by=-metrics.cvss_v3.base_score" \
  | jq '.data[] | {cve_id, title, score: .metrics.cvss_v3.base_score}'
```

### 4 · Alle Produkte eines Herstellers

```bash
curl -s "http://localhost:8000/API/products/?vendor_name=IBM&page_size=50" \
  | jq '.data[] | {id: ._id, name, vendor_name}'
```

### 5 · Vendor-Suche (Volltextsuche)

```bash
curl -s "http://localhost:8000/API/vendors/?search=microsoft" \
  | jq '.data[] | {name, sources}'
```

### 6 · Advisory by ObjectId

```bash
OID="69fe8b71cae57419a40820dd"
curl -s "http://localhost:8000/API/advisories/id/${OID}" | jq .
```

### 7 · Kombinierter Filter (EUVD, Linux, CVSS ≥ 7)

```bash
curl -s "http://localhost:8000/API/advisories/?source=euvd&affected_os=Linux&min_cvss=7.0&page_size=5" \
  | jq '{total: .pagination.total, items: [.data[] | {cve_id, score: .metrics.cvss_v3.base_score}]}'
```

### 8 · Die 100 aktuellsten Advisories (wie Frontend)

```bash
curl -s "http://localhost:8000/API/advisories/?page_size=100&sort_by=-timeline.modified_at" \
  | jq '.data[] | {cve_id, title, modified: .timeline.modified_at}'
```

### 9 · Fuzzy-Suche (Tippfehler-tolerant)

```bash
curl -s "http://localhost:8000/API/advisories/?search=apche+cloudstck&fuzzy=true&page_size=10" \
  | jq '.data[] | {cve_id, title}'
```

### 10 · Advisories mit aktiver Ausnutzung und hohem EPSS

```bash
curl -s "http://localhost:8000/API/advisories/?min_epss=0.8&exploitation_status=exploited&page_size=10&sort_by=-metrics.epss" \
  | jq '.data[] | {cve_id, epss: .metrics.epss, status: .metrics.exploitation_status}'
```

### 11 · Bulk CVE-Lookup

```bash
curl -s "http://localhost:8000/API/advisories/?cve_ids=CVE-2025-1234,CVE-2026-5678" \
  | jq '.data[] | {cve_id, title, score: .metrics.cvss_v3.base_score}'
```

### 12 · Advisories der letzten 7 Tage mit Fix

```bash
curl -s "http://localhost:8000/API/advisories/?published_after=2026-05-22T00:00:00&has_fix=true&page_size=20" \
  | jq '.data[] | {cve_id, title, fixed: .remediation.fixed_versions}'
```

---

## Frontend

```
GRID/frontend/advisories.php
```

PHP-basierte Dark-Mode-Oberfläche mit Server-Side-Pagination. Die Seite zeigt standardmäßig 100 Advisories. Seitenwechsel lösen einzelne API-Requests aus (kein Background-Batch-Loading). Die Suchleiste nutzt den `search`-Parameter der API mit 350ms Debounce.

```bash
# PHP-Dev-Server starten
php -S localhost:8080 -t frontend/
# → http://localhost:8080/advisories.php
```
