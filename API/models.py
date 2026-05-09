"""
models.py — Pydantic models that mirror the GRIDd collection schemas
defined in Architecture.md and validated against the example documents
in GRID/examples/.

All models are used both for response serialisation (FastAPI) and as
self-documenting schema for the auto-generated OpenAPI / Swagger UI.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, List, Optional
from pydantic import BaseModel, Field


# ============================================================
# Shared / primitive models
# ============================================================

class PyObjectId(str):
    """Thin wrapper so MongoDB ObjectIds are serialised as plain strings."""

    @classmethod
    def __get_validators__(cls):
        yield cls.validate

    @classmethod
    def validate(cls, v: Any) -> str:
        return str(v)


# ============================================================
# Advisory (GRIDd / advisories)
# ============================================================

class CvssV3(BaseModel):
    """CVSS v3.x / v4.0 score block."""

    base_score: float = Field(0.0, description="Numeric base score (0.0–10.0).")
    vector: Optional[str] = Field(None, description="Full CVSS vector string.")
    version: Optional[str] = Field(None, description="CVSS specification version, e.g. '3.1' or '4.0'.")


class Metrics(BaseModel):
    cvss_v3: Optional[CvssV3] = None
    cvss_estimated: Optional[bool] = Field(
        None,
        description="True when the CVSS score was estimated from aggregate_severity.text (no numeric score in source data).",
    )
    severity_text: Optional[str] = Field(
        None,
        description="Raw CERT-BUND aggregate severity label, e.g. 'hoch', 'kritisch'.",
    )
    epss: float = Field(0.0, description="EPSS probability score (0.0–1.0).")
    exploitation_status: Optional[str] = Field(
        None,
        description="Human-readable exploitation status, e.g. 'Exploited since 2026-01-15'.",
    )


class AffectedVersion(BaseModel):
    """Single entry in infrastructure.affected_versions."""

    vendor: str = Field("", description="Vendor name (may be empty for EUVD-sourced entries).")
    product: str
    version: str
    is_range: bool = Field(..., description="True if the version string encodes a range (< / >= / ≤).")
    status: str = Field(
        ...,
        description="One of: affected | fixed | last_affected | not_affected.",
    )
    cpe: str = Field("", description="CPE 2.3 URI, empty string if not available.")
    source: str = Field(..., description="Origin ingest source: 'csaf' or 'euvd'.")


class InfraLink(BaseModel):
    """ObjectId cross-reference pair linking an advisory to vendor + product."""

    vendor_id: Optional[str] = Field(None, description="ObjectId string referencing GRIDd/vendors.")
    product_id: Optional[str] = Field(None, description="ObjectId string referencing GRIDd/products.")


class Infrastructure(BaseModel):
    affected_os: List[str] = Field(default_factory=list, description="Affected operating systems.")
    affected_versions: List[AffectedVersion] = Field(default_factory=list)
    links: List[InfraLink] = Field(
        default_factory=list,
        description="FK pairs into the vendors and products collections.",
    )


class Remediation(BaseModel):
    status: Optional[str] = Field(None, description="E.g. 'Patch available'.")
    details: Optional[str] = Field(None, description="Free-text remediation guidance.")
    fixed_versions: List[str] = Field(default_factory=list, description="Flat list of fixed version strings.")


class Timeline(BaseModel):
    published_at: Optional[str] = Field(None, description="ISO-8601 publication timestamp.")
    modified_at: Optional[str] = Field(None, description="ISO-8601 last-modification timestamp.")


class Intel(BaseModel):
    references: List[str] = Field(default_factory=list, description="External reference URLs.")


class AdvisoryMetadata(BaseModel):
    sources: List[str] = Field(default_factory=list, description="Ingest sources that contributed, e.g. ['csaf','euvd'].")
    raw_source_ids: dict = Field(
        default_factory=dict,
        description="Traceability back to GRIDr: {'cert_bund': 'WID-SEC-W-…', 'euvd': 'EUVD-…'}.",
    )
    last_processed: Optional[datetime] = Field(None, description="UTC timestamp of last processing run.")


class Advisory(BaseModel):
    """Full advisory document from GRIDd/advisories."""

    id: Optional[str] = Field(None, alias="_id", description="MongoDB ObjectId as string.")
    cve_id: str = Field(..., description="Canonical CVE identifier, e.g. 'CVE-2026-12345'.")
    title: Optional[str] = Field(None, description="Short advisory title.")
    description: Optional[str] = Field(None, description="Human-readable vulnerability summary.")
    metrics: Optional[Metrics] = None
    infrastructure: Optional[Infrastructure] = None
    remediation: Optional[Remediation] = None
    timeline: Optional[Timeline] = None
    intel: Optional[Intel] = None
    metadata: Optional[AdvisoryMetadata] = None

    model_config = {"populate_by_name": True}


# ============================================================
# Product (GRIDd / products)
# ============================================================

class ProductVersion(BaseModel):
    version_string: str
    is_range: bool
    cpe: str = ""


class Product(BaseModel):
    """Full product document from GRIDd/products."""

    id: Optional[str] = Field(None, alias="_id", description="MongoDB ObjectId as string.")
    name: str = Field(..., description="Normalised product name.")
    vendor_id: Optional[str] = Field(None, description="ObjectId string → GRIDd/vendors.")
    vendor_name: Optional[str] = Field(None, description="Denormalised vendor name for fast queries.")
    raw_names: List[str] = Field(default_factory=list, description="All raw name variants seen in source data.")
    versions: List[ProductVersion] = Field(default_factory=list)
    sources: List[str] = Field(default_factory=list)
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    model_config = {"populate_by_name": True}


# ============================================================
# Vendor (GRIDd / vendors)
# ============================================================

class Vendor(BaseModel):
    """Full vendor document from GRIDd/vendors."""

    id: Optional[str] = Field(None, alias="_id", description="MongoDB ObjectId as string.")
    name: str = Field(..., description="Normalised canonical vendor name (unique).")
    raw_names: List[str] = Field(default_factory=list, description="All raw name variants seen in source data.")
    sources: List[str] = Field(default_factory=list, description="Ingest sources: 'csaf' | 'euvd'.")
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    model_config = {"populate_by_name": True}


# ============================================================
# Status / Metadata endpoint response
# ============================================================

class IngestStatus(BaseModel):
    """Aggregated status snapshot returned by GET /API/status."""

    advisory_count: int = Field(..., description="Total documents in GRIDd/advisories.")
    product_count: int = Field(..., description="Total documents in GRIDd/products.")
    vendor_count: int = Field(..., description="Total documents in GRIDd/vendors.")
    last_ingest: Optional[dict] = Field(
        None,
        description="Most recent metadata record from GRIDd/metadata (may be None if never run).",
    )
