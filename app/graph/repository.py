"""Cypher query functions for upserting and reading the patch intelligence graph.

Every function takes an open Neo4j `Session` so callers (the ingestion
pipeline, tests) control transaction/session lifecycle via `graph_session()`.
"""

from __future__ import annotations

from neo4j import Session

from app.models.domain import CPE, CVE, Patch


def upsert_cve(session: Session, cve: CVE) -> None:
    session.run(
        """
        MERGE (c:CVE {cve_id: $cve_id})
        SET c.description = $description,
            c.cvss_score = $cvss_score,
            c.cvss_severity = $cvss_severity,
            c.published = $published
        """,
        cve_id=cve.cve_id,
        description=cve.description,
        cvss_score=cve.cvss_score,
        cvss_severity=cve.cvss_severity,
        published=cve.published.isoformat() if cve.published else None,
    )


def upsert_cpe(session: Session, cpe: CPE) -> None:
    session.run(
        """
        MERGE (c:CPE {cpe23uri: $uri})
        SET c.vendor = $vendor, c.product = $product, c.version = $version
        """,
        uri=cpe.cpe23uri,
        vendor=cpe.vendor,
        product=cpe.product,
        version=cpe.version,
    )


def link_cve_affects_cpe(session: Session, cve_id: str, cpe_uri: str) -> None:
    session.run(
        """
        MATCH (c:CVE {cve_id: $cve_id}), (p:CPE {cpe23uri: $cpe_uri})
        MERGE (c)-[:AFFECTS]->(p)
        """,
        cve_id=cve_id,
        cpe_uri=cpe_uri,
    )


def upsert_package(session: Session, ecosystem: str, name: str) -> None:
    session.run(
        "MERGE (pkg:Package {ecosystem: $ecosystem, name: $name})",
        ecosystem=ecosystem,
        name=name,
    )


def link_cpe_identifies_package(session: Session, cpe_uri: str, ecosystem: str, name: str) -> None:
    session.run(
        """
        MATCH (c:CPE {cpe23uri: $cpe_uri}), (pkg:Package {ecosystem: $ecosystem, name: $name})
        MERGE (c)-[:IDENTIFIES]->(pkg)
        """,
        cpe_uri=cpe_uri,
        ecosystem=ecosystem,
        name=name,
    )


def upsert_patch(session: Session, patch: Patch, confidence_score: int | None = None) -> None:
    session.run(
        """
        MERGE (p:Patch {patch_id: $patch_id})
        SET p.ecosystem = $ecosystem,
            p.vendor = $vendor,
            p.product = $product,
            p.name = $name,
            p.fixed_version = $fixed_version,
            p.reference_url = $reference_url,
            p.is_eol = $is_eol,
            p.eol_date = $eol_date,
            p.known_issue_count = $known_issue_count,
            p.confidence_score = $confidence_score
        """,
        patch_id=patch.patch_id,
        ecosystem=patch.ecosystem.value,
        vendor=patch.vendor,
        product=patch.product,
        name=patch.name,
        fixed_version=patch.fixed_version,
        reference_url=patch.reference_url,
        is_eol=patch.is_eol,
        eol_date=patch.eol_date.isoformat() if patch.eol_date else None,
        known_issue_count=len(patch.known_issues),
        confidence_score=confidence_score,
    )


def link_patch_fixes_cve(session: Session, patch_id: str, cve_id: str) -> None:
    session.run(
        """
        MATCH (p:Patch {patch_id: $patch_id}), (c:CVE {cve_id: $cve_id})
        MERGE (p)-[:FIXES]->(c)
        """,
        patch_id=patch_id,
        cve_id=cve_id,
    )


def link_patch_applies_to_cpe(session: Session, patch_id: str, cpe_uri: str) -> None:
    session.run(
        """
        MATCH (p:Patch {patch_id: $patch_id}), (c:CPE {cpe23uri: $cpe_uri})
        MERGE (p)-[:APPLIES_TO]->(c)
        """,
        patch_id=patch_id,
        cpe_uri=cpe_uri,
    )


def get_patch_neighborhood(session: Session, cve_id: str) -> list[dict]:
    """Every patch that fixes this CVE, with the CPE it applies to, ranked by confidence."""
    result = session.run(
        """
        MATCH (cve:CVE {cve_id: $cve_id})<-[:FIXES]-(patch:Patch)-[:APPLIES_TO]->(cpe:CPE)
        RETURN patch, cpe
        ORDER BY patch.confidence_score DESC
        """,
        cve_id=cve_id,
    )
    return [dict(record) for record in result]


def get_package_patches(session: Session, ecosystem: str, name: str) -> list[dict]:
    """All known patches for a given ecosystem package, newest version first."""
    result = session.run(
        """
        MATCH (pkg:Package {ecosystem: $ecosystem, name: $name})<-[:IDENTIFIES]-(cpe:CPE)
              <-[:APPLIES_TO]-(patch:Patch)
        RETURN patch, cpe
        ORDER BY patch.fixed_version DESC
        """,
        ecosystem=ecosystem,
        name=name,
    )
    return [dict(record) for record in result]


def get_patch(session: Session, patch_id: str) -> dict | None:
    result = session.run(
        "MATCH (p:Patch {patch_id: $patch_id}) RETURN p AS patch",
        patch_id=patch_id,
    )
    record = result.single()
    return dict(record["patch"]) if record else None
