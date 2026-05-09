As Of 08.05.2026 at 23:30CEST The Architecture Of GRID Changes away from a "Throw it all together" approach to a more structured, scalable, and maintainable architecture. A more modular and well-designed approach is being taken. The goal is to create a system that is easy to extend, maintain, and understand.

<br>
<p align="center">
  <img src="media/database-raw.svg" width="75" alt="Database Raw">
  <img src="media/database.svg" width="75" alt="Database Enriched">
  <img src="media/ingest.svg" width="75" alt="Ingest">
  <img src="media/mapping.svg" width="75" alt="Mapping">
  <img src="media/scheme.svg" width="75" alt="Schema">
</p>

## The Database:

The original Database "GRID" will be Split into 2 Differing Databases:

1. GRID-Raw (GRIDr)
2. GRID-Data (GRIDd)

### GRIDr:

Ingest scripts will directly Ingest data from the sources into this database. No processing will be done. This is purely for Archival purposes.
The "Raw" in the database name comes from the fact that the data is stored in its raw format, without any modifications.

Planned Tables:

- CERT-BUND (_data from cert-bund-raw.py_)
- EUVD (_data from euvd-raw.py_)
- Metadata (_stores metadata about the ingest process, e.g. timestamps, last ingest ID, successful/unsuccessful ingest flags, error logs, etc._)

### GRIDd:

This database will store the processed data from the "GRID-Raw" database. This allows the backend to enrich, dedublicate and map data without any rate limitations or anything. Also this allows for a well documented state of the data as the processed RAW data from the sources will be changed into a custom format with processed database objects.

Planned Collections/Tables:

- Vulnerabilities
- Vendors
- Products
- Metadata (_basically the same as the GRIDr Metadata collection_)

## The Enrichment Pipeline:

After this more or less radical change in architecture, the enrichment pipeline will not be necessary anymore. This is due to the fact that the primary ingest scripts "**cert-bund-raw.py**" and "**euvd-raw.py**" already contain all basic needed information including:

- CVE's
- CVSS Scores
- Affected Products
- Affected Versions
- Affected Software
- Remediation Info (_e.g. Patch, Workaround, etc._)

Therefore the enrichment pipeline will be removed in favor of a join pipeline.

## The Ingest Pipeline:

The basic functionality of the ingest scripts will be sustained. Pre restrucutre Scripts have the technical capability to push the data needed into the GRIDr database without any problems. The only changes needed will be some slight metadata adjustments and the like.

One example is the removal of seperation logic in the current "**csaf.py**" (will be renamed to "**csaf-ingest.py**") which currently extracts vendor and productt information and stores them seperately. This is not needed since the ingest will only pull raw and unchanged information into the GRIDr database.

## The Dedublication / Mapping / Join Pipeline:

This pipeline will be responsible for taking the "**GRIDr**" database and processing it into the "**GRIDd**" database. It will look for Data it can map (_e.g. CVE-IDs, Base-Scores, etc._) and join them together to create a complete picture of the vulnerability. This pipeline will be much more sophisticated than the current enrichment pipeline and will be able to handle complex join logic.

This will also replace the current enrichment logic.

To know what entries it can map to eachother, there will be a JSON document containing Mapping Logic. This mapping logic will define how to map data from one source to the other.

## The Vendor & Product Extraction Logic:

Currently, the "**csaf.py**" script extracts vendor and product information and stores them seperately in the MongoDB database. This is not needed since the ingest will only pull raw and unchanged information into the GRIDr database.

The product and vendor extraction logic will extract the data directly from GRIDr. This way no information will be lost. The only problem with that is that sometimes data has some extensions to it. For example in csaf files vendor and product data can be split into different objects, or some vendors like RedHat add their name infront of the product name or sometimes the vendor uses their business name (_e.g. Microsoft GmbH_) insted of just (_e.g. Microsoft_).

By using a seperate products.json and vendors.json, there can be defined rules of how to parse out these "extensions".
Also the extraction logic can use a smart logic to check for example product names for the vendor name. (_e.g. the vendor "RedHat" is present in product name "RedHat Enterprise Linux"_)

This way there is no information lost and the products and vendors are stored in a structured and normalized way.

## MongoDB Schema:

```text
GRIDr/
├── cert-bund/ (contains cve/csaf data)
├── euvd/ (contains cve/euvd data)
└── metadata/ (contains metadata about the ingest process, e.g. timestamps, last ingest ID, successful/unsuccessful ingest flags, error logs, etc.)
```

```text
GRIDd/
├── advisories/ (contains processed csaf/euvd data)
├── products/ (contains software/product data)
├── vendors/ (contains vendor data)
└── metadata/ (contains metadata about the ingest process, e.g. timestamps, last ingest ID, successful/unsuccessful ingest flags, error logs, etc.)
```

## GRIDd Collection Schemas:

The following shows the actual document structure stored in each GRIDd collection.
These are produced by the processing pipeline (`vendors.py`, `products.py`, `join.py`).

### GRIDd / vendors

```json
{
  "_id":       "ObjectId",
  "name":      "Apache",
  "raw_names": ["Apache"],
  "sources":   ["csaf", "euvd"],
  "created_at": "ISODate",
  "updated_at": "ISODate"
}
```

| Field | Description |
|---|---|
| `name` | Normalized canonical vendor name (unique index) |
| `raw_names` | All raw name variants seen across source documents |
| `sources` | Which ingest sources contributed (`csaf`, `euvd`) |

---

### GRIDd / products

```json
{
  "_id":         "ObjectId",
  "name":        "Cloudstack",
  "vendor_id":   "ObjectId → vendors._id",
  "vendor_name": "Apache",
  "raw_names":   ["CloudStack", "Apache CloudStack"],
  "versions": [
    { "version_string": "LTS <4.20.3.0", "is_range": true,  "cpe": "" },
    { "version_string": "LTS 4.20.3.0",  "is_range": false, "cpe": "cpe:/a:apache:cloudstack:lts__4.20.3.0" }
  ],
  "sources":    ["csaf"],
  "created_at": "ISODate",
  "updated_at": "ISODate"
}
```

| Field | Description |
|---|---|
| `name` | Normalized product name (unique per vendor) |
| `vendor_id` | FK → `GRIDd/vendors._id` |
| `vendor_name` | Denormalized for efficient querying |
| `versions` | All known version strings with CPE and range flag |
| `sources` | Which ingest sources contributed |

---

### GRIDd / advisories

```json
{
  "_id":         "ObjectId",
  "cve_id":      "CVE-2026-12345",
  "title":       "Apache CloudStack: Mehrere Schwachstellen",
  "description": "Summary text from CERT-BUND (falls back to EUVD description).",

  "metrics": {
    "cvss_v3": {
      "base_score": 9.8,
      "vector":     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
      "version":    "3.1"
    },
    "epss":               0.9412,
    "exploitation_status": "Exploited since 2026-01-15"
  },

  "infrastructure": {
    "affected_os": ["Linux", "UNIX"],
    "affected_versions": [
      {
        "vendor":   "Apache",
        "product":  "CloudStack",
        "version":  "LTS <4.20.3.0",
        "is_range": true,
        "status":   "affected",
        "cpe":      "",
        "source":   "csaf"
      },
      {
        "vendor":   "Apache",
        "product":  "CloudStack",
        "version":  "LTS 4.20.3.0",
        "is_range": false,
        "status":   "fixed",
        "cpe":      "cpe:/a:apache:cloudstack:lts__4.20.3.0",
        "source":   "csaf"
      }
    ],
    "links": [
      { "vendor_id": "ObjectId → vendors._id", "product_id": "ObjectId → products._id" }
    ]
  },

  "remediation": {
    "status":         "Patch available",
    "details":        "Update to version 4.20.3.0 or later.",
    "fixed_versions": ["LTS 4.20.3.0", "LTS 4.22.0.1"]
  },

  "timeline": {
    "published_at": "2026-05-07T22:00:00Z",
    "modified_at":  "2026-05-08T11:40:00Z"
  },

  "intel": {
    "references": [
      "https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-1438",
      "https://nvd.nist.gov/vuln/detail/CVE-2026-12345"
    ]
  },

  "metadata": {
    "sources":        ["csaf", "euvd"],
    "raw_source_ids": {
      "cert_bund": "WID-SEC-W-2026-1438",
      "euvd":      "EUVD-2026-28582"
    },
    "last_processed": "ISODate"
  }
}
```

| Field | Description |
|---|---|
| `cve_id` | Unique index — one document per CVE across all sources |
| `metrics.cvss_v3` | CERT-BUND primary; EUVD fallback if CSAF has no score |
| `metrics.epss` | EUVD only (EPSS probability score) |
| `infrastructure.affected_versions` | All affected + fixed version entries; `status` ∈ `{affected, fixed, last_affected, not_affected}` |
| `infrastructure.links` | ObjectId FKs into `GRIDd/vendors` and `GRIDd/products` |
| `remediation.fixed_versions` | Flat list of fixed version strings (derived from `affected_versions`) |
| `metadata.raw_source_ids` | Traceability back to original GRIDr documents |

