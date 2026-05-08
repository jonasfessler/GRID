<p align="center">
  <img src="media/logo.svg" width="250" alt="GRID Logo">
</p>

**GRID** (Global Risk Intelligence Dashboard) ist eine hochperformante, asynchrone Pipeline zur Erfassung, Normalisierung und intelligenten Anreicherung von Cyber-Sicherheitswarnmeldungen. Das System transformiert heterogene CSAF-Daten (Common Security Advisory Framework) in eine strukturierte, deduplizierte Wissensdatenbank.

## Kernfunktionen

- **Asynchroner CSAF-Ingest:** Effizientes Abrufen und Verarbeiten von Security Advisories (z. B. vom CERT-Bund) mittels `httpx` und `asyncio`.
- **Strikte Daten-Normalisierung:** Automatisierte Trennung von Herstellern (Vendors) und Produkten in der Datenbank zur Vermeidung von Redundanzen.
- **Intelligente EUVD-Anreicherung:** Integration der ENISA European Vulnerability Database (EUVD). Ergänzt Schwachstellen um CVSS-Vektoren, EPSS-Scores und den KEV-Status (Known Exploited Vulnerabilities).
- **Kryptografische Deduplizierung:** Zusammenführung identischer Schwachstellen aus verschiedenen Quellen unter einer eindeutigen, 16-stelligen Hex-`GRID-ID`.
- **Zentrales Queue-Management:** Aufgabenbasiertes System zur Steuerung der Verarbeitungsphasen (Ingest → Enrichment → Deduplication).

## Tech Stack

- **Backend:** Python 3.11+ (Bibliotheken: `motor`, `httpx`, `pymongo`, `beautifulsoup4`).
- **Datenbank:** MongoDB 7.0+ (NoSQL).
- **Infrastruktur:** Docker zur Containerisierung der Datenbank.
- **Frontend-Schnittstelle:** PHP (Public Web Entry Point).

## Projektstruktur

```text
GRID/
├── backend/
│   ├── ingest/       # Skripte für den CSAF-Import (csaf.py)
│   ├── enrich/       # Dienste zur EUVD-Datenanreicherung (enrich.py)
│   └── dedublicate/  # Logik zur Konsolidierung und GRID-ID Vergabe
└── frontend/         # Öffentlich erreichbare Web-Dateien (index.php)
```

Mehr über die Architecture kann man in der [Architecture.md](Architecture.md) finden.

<br>
<p align="center">
  <img src="media/database-raw.svg" width="75" alt="Database Raw">
  <img src="media/database.svg" width="75" alt="Database Enriched">
  <img src="media/ingest.svg" width="75" alt="Ingest">
  <img src="media/mapping.svg" width="75" alt="Mapping">
  <img src="media/scheme.svg" width="75" alt="Schema">
</p>
