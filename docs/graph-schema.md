# Graph schema

Patch Guard models patch intelligence as a bidirectional knowledge graph,
following the CVE → CPE → Patch structure the project is built around.

## Nodes

| Label | Key property | Other properties |
|---|---|---|
| `CVE` | `cve_id` | `description`, `cvss_score`, `cvss_severity`, `published` |
| `CPE` | `cpe23uri` | `vendor`, `product`, `version` |
| `Package` | `(ecosystem, name)` | `ecosystem` |
| `Patch` | `patch_id` | `ecosystem`, `vendor`, `product`, `fixed_version`, `reference_url`, `is_eol`, `eol_date`, `known_issues` (serialized), `confidence_score` |

## Relationships

| Relationship | Direction | Meaning |
|---|---|---|
| `AFFECTS` | `(CVE)-[:AFFECTS]->(CPE)` | This CVE impacts this vendor/product/version |
| `IDENTIFIES` | `(CPE)-[:IDENTIFIES]->(Package)` | This CPE maps to this ecosystem package |
| `FIXES` | `(Patch)-[:FIXES]->(CVE)` | This patch resolves this CVE |
| `APPLIES_TO` | `(Patch)-[:APPLIES_TO]->(CPE)` | This patch is the fix for this vendor/product/version |
| `SUPERSEDES` | `(Patch)-[:SUPERSEDES]->(Patch)` | Version ordering / supersedence within a product |

## Why Neo4j over a SQL table

The original brief (and the old reference implementation) stores this as a
flat correlation table. That makes the two questions this project exists to
answer — *"what fixes this CVE"* and *"what does applying this patch put me
on the hook for"* — expensive joins instead of graph traversals. Modeling it
natively as a graph makes both a one-hop (or shortest-path) Cypher query.

Example: everything needed to decide whether to apply a patch for a given
CVE, in one query:

```cypher
MATCH (cve:CVE {cve_id: $cve_id})<-[:FIXES]-(patch:Patch)-[:APPLIES_TO]->(cpe:CPE)
RETURN patch, cpe, patch.confidence_score
ORDER BY patch.confidence_score DESC
```
