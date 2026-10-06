"""Collector/correlator for the NVD CVE API 2.0 — CVE <-> CPE correlation.

NVD's own patch references mostly point to advisories rather than the actual
fixed artifact, which is exactly the disconnect this project exists to close:
we use NVD only for what it's authoritative on (CVE descriptions, CVSS
severity, and the CPEs a CVE is configured against), and let the ecosystem
collectors supply the real fixed-version data.
"""

from __future__ import annotations

import os
from datetime import datetime

import httpx

from app.models.domain import CPE, CVE

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


async def search_cves_by_keyword(
    client: httpx.AsyncClient, keyword: str, results_limit: int = 50
) -> list[CVE]:
    """Query NVD for CVEs matching a product keyword and extract CVSS +
    affected-CPE data from each result's configurations.
    """
    headers = {}
    api_key = os.getenv("NVD_API_KEY")
    if api_key:
        headers["apiKey"] = api_key

    resp = await client.get(
        NVD_API_URL,
        params={"keywordSearch": keyword, "resultsPerPage": results_limit},
        headers=headers,
    )
    resp.raise_for_status()
    data = resp.json()

    cves = []
    for vuln in data.get("vulnerabilities", []):
        cve_data = vuln.get("cve", {})
        cve_id = cve_data.get("id")
        if not cve_id:
            continue

        description = next(
            (d["value"] for d in cve_data.get("descriptions", []) if d.get("lang") == "en"),
            "",
        )
        cvss_score, cvss_severity = _extract_cvss(cve_data.get("metrics", {}))

        cves.append(
            CVE(
                cve_id=cve_id,
                description=description,
                cvss_score=cvss_score,
                cvss_severity=cvss_severity,
                published=_parse_time(cve_data.get("published")),
                cpe_match_uris=_extract_cpe_uris(cve_data.get("configurations", [])),
            )
        )
    return cves


def cpes_from_uris(uris: list[str]) -> list[CPE]:
    """Parse CPE 2.3 URIs (`cpe:2.3:part:vendor:product:version:...`) into models."""
    cpes = []
    for uri in uris:
        parts = uri.split(":")
        if len(parts) < 6:
            continue
        vendor, product, version = parts[3], parts[4], parts[5]
        cpes.append(
            CPE(
                cpe23uri=uri,
                vendor=vendor,
                product=product,
                version=None if version == "*" else version,
            )
        )
    return cpes


def _extract_cvss(metrics: dict) -> tuple[float | None, str | None]:
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key)
        if entries:
            cvss_data = entries[0].get("cvssData", {})
            severity = cvss_data.get("baseSeverity") or entries[0].get("baseSeverity")
            return cvss_data.get("baseScore"), severity
    return None, None


def _extract_cpe_uris(configurations: list[dict]) -> list[str]:
    uris = []
    for config in configurations:
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                if match.get("vulnerable") and match.get("criteria"):
                    uris.append(match["criteria"])
    return uris


def _parse_time(raw: str | None) -> datetime | None:
    if not raw:
        return None
    return datetime.fromisoformat(raw)
