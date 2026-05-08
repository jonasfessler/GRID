# GRID (Global Risk Intelligence Dashboard)

<p align="center">
  <img src="media/logo.svg" width="250" alt="GRID Logo">
</p>

**GRID** is a high-performance, asynchronous pipeline designed for the ingestion, normalization, and intelligent mapping of cybersecurity advisories. The system follows a modular architecture to transform heterogeneous security data into a structured and deduplicated knowledge base.

## Core Features

- **Asynchronous Raw Ingest:** Efficiently mirrors security advisories from sources like CERT-Bund and ENISA (EUVD) using `httpx` and `asyncio`.
- **Medallion Architecture:** Separates raw archival data (GRIDr) from processed, enriched data (GRIDd) to ensure data sovereignty and scalability.
- **Intelligent Normalization:** Automated extraction and normalization of vendors and products using rule-based JSON definitions.
- **Advanced Join Pipeline:** Replaces traditional enrichment with a sophisticated join logic that maps CVE-IDs, CVSS scores, and remediation info across different sources.
- **Idempotent Processing:** Change-detection mechanisms ensure that only new or updated advisories are processed, minimizing database writes.

## Architecture Overview

The system is split into two primary database layers:

1.  **GRIDr (Raw):** Stores unchanged JSON documents directly from the source for archival purposes.
2.  **GRIDd (Data):** Contains the refined state of the data, including deduplicated vulnerabilities and normalized vendor/product collections.

For a deep dive into the system design, please refer to the [Architecture.md](Architecture.md).

## Tech Stack

- **Backend:** Python 3.11+ (Core libraries: `motor`, `httpx`, `asyncio`, `beautifulsoup4`).
- **Database:** MongoDB 7.0+ (NoSQL).
- **Infrastructure:** Docker for database containerization.
- **Frontend Interface:** PHP (Public Web Entry Point).

## Project Structure

```text
GRID/
├── backend/
│   ├── ingest/       # Raw ingest scripts (cert-bund-raw.py, euvd-raw.py)
│   ├── mapping.json  # Logic for joining data sources
│   ├── products.json # Rules for product extraction/normalization
│   └── vendors.json  # Rules for vendor extraction/normalization
├── media/            # Architecture diagrams and assets
└── frontend/         # Web-facing files
```
