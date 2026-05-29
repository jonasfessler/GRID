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

- **Backend:** Python 3.11+ (Core libraries: `motor`, `httpx`, `h2`, `asyncio`, `beautifulsoup4`).
- **API:** FastAPI 2.0+, Pydantic 2.0+, rapidfuzz (fuzzy search), uvicorn.
- **Database:** MongoDB 7.0+ (NoSQL).
- **Infrastructure:** Docker for database containerization.
- **Frontend Interface:** PHP (Public Web Entry Point).

## Installation

Install backend dependencies via `apt` (`asyncio` is part of the Python standard library and needs no installation):

```bash
sudo apt install python3-httpx python3-h2 python3-bs4 python3-motor python3-uvicorn php
```

Install API dependencies:

```bash
pip install -r API/requirements.txt
```

## Project Structure

```text
GRID/
├── API/              # FastAPI REST-API (v2.0)
│   ├── main.py       # App factory, lifespan, /API/status
│   ├── database.py   # Motor client, index management
│   ├── models.py     # Pydantic models
│   ├── utils.py      # Helpers, TTLCache, sort allow-lists
│   ├── requirements.txt
│   └── routers/
│       ├── advisories.py
│       ├── products.py
│       └── vendors.py
├── backend/
│   ├── ingest/       # Raw ingest scripts (cert-bund-raw.py, euvd-raw.py)
│   ├── mapping.json  # Logic for joining data sources
│   ├── products.json # Rules for product extraction/normalization
│   └── vendors.json  # Rules for vendor extraction/normalization
├── media/            # Architecture diagrams and assets
└── frontend/         # Web-facing files (PHP)
```
