"""Neo4j schema: constraints and indexes for the patch intelligence graph.

Node labels: CVE, CPE, Patch, Package
Relationship types:
  (CVE)-[:AFFECTS]->(CPE)
  (CPE)-[:IDENTIFIES]->(Package)
  (Patch)-[:FIXES]->(CVE)
  (Patch)-[:APPLIES_TO]->(CPE)
  (Patch)-[:SUPERSEDES]->(Patch)

These statements are idempotent (`IF NOT EXISTS`) so `apply_schema` can be
called on every startup without special-casing a fresh database.
"""

SCHEMA_STATEMENTS: list[str] = [
    "CREATE CONSTRAINT cve_id IF NOT EXISTS FOR (c:CVE) REQUIRE c.cve_id IS UNIQUE",
    "CREATE CONSTRAINT cpe_uri IF NOT EXISTS FOR (c:CPE) REQUIRE c.cpe23uri IS UNIQUE",
    "CREATE CONSTRAINT patch_id IF NOT EXISTS FOR (p:Patch) REQUIRE p.patch_id IS UNIQUE",
    "CREATE CONSTRAINT package_key IF NOT EXISTS FOR (pkg:Package) "
    "REQUIRE (pkg.ecosystem, pkg.name) IS UNIQUE",
    "CREATE INDEX patch_ecosystem IF NOT EXISTS FOR (p:Patch) ON (p.ecosystem)",
    "CREATE INDEX patch_product IF NOT EXISTS FOR (p:Patch) ON (p.product)",
    "CREATE INDEX cve_severity IF NOT EXISTS FOR (c:CVE) ON (c.cvss_severity)",
]


def apply_schema(session) -> None:
    """Run all schema statements against an open Neo4j session."""
    for statement in SCHEMA_STATEMENTS:
        session.run(statement)
