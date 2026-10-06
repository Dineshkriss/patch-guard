from __future__ import annotations

from datetime import date, datetime
from enum import StrEnum

from pydantic import BaseModel, Field


class Ecosystem(StrEnum):
    NPM = "npm"
    PYPI = "pypi"
    MAVEN = "maven"
    NUGET = "nuget"
    LINUX = "linux"


class IssueCategory(StrEnum):
    CRASH = "crash"
    PERFORMANCE = "performance"
    REBOOT_REQUIRED = "reboot_required"
    BREAKING_CHANGE = "breaking_change"
    OTHER = "other"


class CVE(BaseModel):
    """A CVE record pulled from the NVD CVE API, scoped to the CPEs it affects."""

    cve_id: str
    description: str
    cvss_score: float | None = None
    cvss_severity: str | None = None
    published: datetime | None = None
    cpe_match_uris: list[str] = Field(default_factory=list)


class CPE(BaseModel):
    """A Common Product Enumeration identifying a vendor/product/version triple."""

    cpe23uri: str
    vendor: str
    product: str
    version: str | None = None


class KnownIssue(BaseModel):
    """A risk/crash-intelligence signal attached to a specific patch version.

    Populated heuristically from changelog/release-note text — see
    app/scoring/confidence.py for how these feed into the confidence score.
    """

    category: IssueCategory
    description: str
    source_url: str | None = None


class Patch(BaseModel):
    """The actionable patch record — mirrors the structure required by the
    project brief: vendor, product, fixed version, reference KB, CVEs fixed,
    and the corresponding NVD CPE.
    """

    ecosystem: Ecosystem
    vendor: str
    product: str
    name: str
    fixed_version: str
    reference_url: str | None = None
    released_at: datetime | None = None
    vulnerabilities_fixed: list[str] = Field(default_factory=list)  # CVE IDs
    cpe23uri: str | None = None
    known_issues: list[KnownIssue] = Field(default_factory=list)
    is_eol: bool = False
    eol_date: date | None = None

    @property
    def patch_id(self) -> str:
        return f"{self.ecosystem}:{self.product}:{self.fixed_version}"


class ConfidenceScore(BaseModel):
    """The computed 0-100 confidence score for a patch, with a transparent
    breakdown of the contributing factors (see docs/confidence-score.md).
    """

    patch_id: str
    score: int
    breakdown: dict[str, float]
    computed_at: datetime
