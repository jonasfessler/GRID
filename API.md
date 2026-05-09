# GRID API — Dokumentation

Asynchrone REST-API auf Basis von **FastAPI**, die verarbeitete Schwachstellendaten aus der **GRIDd**-MongoDB-Datenbank bereitstellt. Alle Antworten sind JSON.

---

## Starten

```bash
cd /home/vrse/Webenwicklung/GRID

# Abhängigkeiten installieren (einmalig)
pip install fastapi[standard] motor

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
├── main.py            ← FastAPI-App, Lifespan, Router-Mounting, /API/status
├── database.py        ← AsyncIOMotorClient, Collection-Accessors, connect/close
├── models.py          ← Pydantic-Modelle (Advisory, Product, Vendor, IngestStatus)
├── utils.py           ← ObjectId-Konverter, Pagination-Helper
├── requirements.txt
├── CURL_EXAMPLES.md
└── routers/
    ├── __init__.py
    ├── advisories.py  ← GET /API/advisories/, /{cve_id}, /id/{oid}
    ├── products.py    ← GET /API/products/, /{oid}
    └── vendors.py     ← GET /API/vendors/, /{oid}
```

---

## Endpunkte

### Status

| Methode | Pfad | Beschreibung |
|---|---|---|
| `GET` | `/API/status` | Collection-Counts + letzter Ingest-Datensatz aus `GRIDd/metadata` |

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
| `GET` | `/API/advisories/` | Paginierte Liste mit optionalen Filtern |
| `GET` | `/API/advisories/{cve_id}` | Advisory by CVE-ID (exakt, z. B. `CVE-2026-12345`) |
| `GET` | `/API/advisories/id/{object_id}` | Advisory by MongoDB ObjectId |

**Query-Parameter für `GET /API/advisories/`:**

| Parameter | Typ | Default | Beschreibung |
|---|---|---|---|
| `page` | int | `1` | Seite (1-basiert) |
| `page_size` | int | `25` | Einträge pro Seite (max. 200) |
| `min_cvss` | float | — | CVSS-Score ≥ Wert (0.0–10.0) |
| `max_cvss` | float | — | CVSS-Score ≤ Wert (0.0–10.0) |
| `vendor_name` | string | — | Substring-Match auf `affected_versions.vendor` (case-insensitive) |
| `product_name` | string | — | Substring-Match auf `affected_versions.product` (case-insensitive) |
| `source` | string | — | Ingest-Quelle: `csaf` oder `euvd` |
| `affected_os` | string | — | Substring-Match auf `infrastructure.affected_os` |
| `remediation_status` | string | — | Substring-Match auf `remediation.status` |
| `sort_by` | string | `timeline.published_at` | Sortierfeld; `-`-Prefix für Descending (z. B. `-metrics.cvss_v3.base_score`) |

---

### Products (`GRIDd/products`)

| Methode | Pfad | Beschreibung |
|---|---|---|
| `GET` | `/API/products/` | Paginierte Liste mit optionalen Filtern |
| `GET` | `/API/products/{object_id}` | Vollständiges Produkt-Dokument inkl. aller Versionen |

**Query-Parameter für `GET /API/products/`:**

| Parameter | Typ | Beschreibung |
|---|---|---|
| `page` / `page_size` | int | Pagination (max. 200) |
| `vendor_name` | string | Substring-Match auf `vendor_name` |
| `product_name` | string | Substring-Match auf `name` |
| `source` | string | `csaf` oder `euvd` |

---

### Vendors (`GRIDd/vendors`)

| Methode | Pfad | Beschreibung |
|---|---|---|
| `GET` | `/API/vendors/` | Paginierte Liste, alphabetisch sortiert |
| `GET` | `/API/vendors/{object_id}` | Einzelner Vendor by ObjectId |

**Query-Parameter für `GET /API/vendors/`:**

| Parameter | Typ | Beschreibung |
|---|---|---|
| `page` / `page_size` | int | Pagination (max. 200) |
| `vendor_name` | string | Substring-Match auf `name` |
| `source` | string | `csaf` oder `euvd` |

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

### 5 · Vendor-Suche (Substring)

```bash
curl -s "http://localhost:8000/API/vendors/?vendor_name=micro" \
  | jq '.data[] | {name, sources, raw_names}'
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
curl -s "http://localhost:8000/API/advisories/?page_size=100&sort_by=-timeline.published_at" \
  | jq '.data[] | {cve_id, title, published: .timeline.published_at}'
```

---

## Frontend

```
GRID/frontend/index.php
```

Temporäre PHP-Seite, die die 100 aktuellsten Advisories über die API lädt und als Dark-Mode-Dashboard rendert.

```bash
# PHP-Dev-Server starten
php -S localhost:8080 -t /home/vrse/Webenwicklung/GRID/frontend/
# → http://localhost:8080
```
