"""The ingestion pipeline: collect -> correlate -> score -> graph upsert.

Correlation is deliberately coarse for this MVP: a CVE is linked to a
package if any of its CPE match entries name that exact product. This
catches the common case (NVD's CPE product field matches the registry
package name) but doesn't resolve version-range matching precisely — a
patch may be linked to CVEs it doesn't actually fix until per-version CPE
matching is added. See docs/ARCHITECTURE.md for the planned improvement.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime

from app.collectors import eol, linux, maven, npm, nuget, nvd, pypi
from app.collectors.base import new_http_client
from app.graph.client import graph_session
from app.graph.repository import (
    link_cpe_identifies_package,
    link_cve_affects_cpe,
    link_patch_applies_to_cpe,
    link_patch_fixes_cve,
    upsert_cpe,
    upsert_cve,
    upsert_package,
    upsert_patch,
)
from app.graph.schema import apply_schema
from app.models.domain import CPE, CVE, Ecosystem, Patch
from app.scoring.confidence import score_patch

_COLLECTORS = {
    Ecosystem.NPM: npm.collect,
    Ecosystem.PYPI: pypi.collect,
    Ecosystem.MAVEN: maven.collect,
    Ecosystem.NUGET: nuget.collect,
    Ecosystem.LINUX: linux.collect,
}


async def ingest_package(
    ecosystem: Ecosystem, package_name: str, *, max_versions: int = 15
) -> list[Patch]:
    """Collect, correlate, score, and load one package's recent patch
    history into the graph. Returns the ingested patches.
    """
    collector = _COLLECTORS[ecosystem]

    async with new_http_client() as client:
        patches = _most_recent(await collector(client, package_name), max_versions)
        cves = await nvd.search_cves_by_keyword(client, package_name)
        matching_cpes = _cpes_for_package(cves, package_name)

        for patch in patches:
            patch.vulnerabilities_fixed = [
                cve.cve_id
                for cve in cves
                if any(cpe.cpe23uri in cve.cpe_match_uris for cpe in matching_cpes)
            ]
            if ecosystem is Ecosystem.LINUX:
                release = _debian_release(patch.name)
                patch.is_eol, patch.eol_date = await eol.get_eol_status(client, "debian", release)

    with graph_session() as session:
        apply_schema(session)
        _store(session, ecosystem, package_name, patches, cves, matching_cpes)

    return patches


def _store(
    session,
    ecosystem: Ecosystem,
    package_name: str,
    patches: list[Patch],
    cves: list[CVE],
    matching_cpes: list[CPE],
) -> None:
    upsert_package(session, ecosystem.value, package_name)

    for cve in cves:
        upsert_cve(session, cve)
    for cpe in matching_cpes:
        upsert_cpe(session, cpe)
        link_cpe_identifies_package(session, cpe.cpe23uri, ecosystem.value, package_name)
        for cve in cves:
            if cpe.cpe23uri in cve.cpe_match_uris:
                link_cve_affects_cpe(session, cve.cve_id, cpe.cpe23uri)

    for patch in patches:
        score = score_patch(patch)
        upsert_patch(session, patch, confidence_score=score.score)
        for cve_id in patch.vulnerabilities_fixed:
            link_patch_fixes_cve(session, patch.patch_id, cve_id)
        for cpe in matching_cpes:
            link_patch_applies_to_cpe(session, patch.patch_id, cpe.cpe23uri)


def _cpes_for_package(cves: list[CVE], package_name: str) -> list[CPE]:
    normalized = package_name.lower().replace("_", "-")
    all_uris = {uri for cve in cves for uri in cve.cpe_match_uris}
    cpes = nvd.cpes_from_uris(list(all_uris))
    return [cpe for cpe in cpes if cpe.product.lower().replace("_", "-") == normalized]


def _most_recent(patches: list[Patch], limit: int) -> list[Patch]:
    def sort_key(patch: Patch) -> datetime:
        return patch.released_at or datetime.min.replace(tzinfo=UTC)

    return sorted(patches, key=sort_key, reverse=True)[:limit]


def _debian_release(patch_name: str) -> str:
    match = re.search(r"\(([^)]+)\)", patch_name)
    return match.group(1) if match else ""
