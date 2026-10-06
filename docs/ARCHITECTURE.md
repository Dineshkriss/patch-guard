# Architecture

## Pipeline

```
┌─────────────┐   ┌──────────────┐   ┌───────────────┐   ┌──────────────┐
│  Collectors │──▶│  Correlation │──▶│    Scoring     │──▶│  Graph store │
│ npm / PyPI  │   │  NVD CVE API │   │  confidence.py │   │    Neo4j     │
│ Maven/NuGet │   │  endoflife   │   │                │   │              │
│ Debian      │   │  .date       │   │                │   │              │
└─────────────┘   └──────────────┘   └───────────────┘   └──────┬───────┘
                                                                  │
                                                           ┌──────▼───────┐
                                                           │  FastAPI     │
                                                           │  REST layer  │
                                                           └──────────────┘
```

All of this is orchestrated by [`app/pipeline/ingest.py`](../app/pipeline/ingest.py)
via `ingest_package(ecosystem, package_name)`, invoked either from
[`scripts/seed.py`](../scripts/seed.py) (CLI) or the scheduled GitHub Actions
workflow ([`.github/workflows/refresh-data.yml`](../.github/workflows/refresh-data.yml)).

## Module map

| Module | Responsibility |
|---|---|
| `app/models/domain.py` | Pydantic models: `CVE`, `CPE`, `Patch`, `KnownIssue`, `ConfidenceScore` |
| `app/collectors/` | One module per data source — each exposes an async `collect()`/lookup function, no shared state |
| `app/scoring/confidence.py` | The 0-100 confidence formula + changelog keyword heuristic |
| `app/graph/` | Neo4j driver singleton, schema (constraints/indexes), and the Cypher repository functions |
| `app/pipeline/ingest.py` | Orchestration: wires collectors → correlation → scoring → graph writes |
| `app/api/` | FastAPI routes over the graph (read-only; all writes go through the pipeline) |

## Design decisions and known limitations

**Correlation is name-based, not version-range-based.** A CVE is linked to a
package if any of its NVD CPE matches share the same `product` field as the
registry package name. This is a deliberate MVP simplification — NVD's CPE
match entries carry `versionStartIncluding`/`versionEndExcluding` fields that
would allow precise per-version correlation, but parsing and reconciling
those against each ecosystem's own version-ordering semantics (semver for
npm/PyPI, OSGi-ish ranges for Maven, etc.) is a meaningfully bigger piece of
work. The current approach over-attributes CVEs to patches (a patch may get
linked to a CVE it doesn't actually fix) — correct for discovery ("is this
product associated with any CVEs"), not yet precise for "does this exact
version fix this exact CVE." Tightening this is the highest-value next step.

**The Neo4j driver is synchronous.** FastAPI route handlers call the sync
`neo4j` driver directly rather than the async variant. For an API that's
read-mostly and backed by indexed point lookups, the latency cost is
negligible; it keeps the repository layer simple to read and test. Swapping
to `AsyncGraphDatabase` is a contained change if/when write-heavy concurrent
load becomes a concern.

**Known issues are a keyword heuristic, not a classifier.** There's no
structured, cross-ecosystem feed for "this patch causes crashes" — the
project brief itself says this has to come from "vendor disclosures, open
source, forums etc." `detect_known_issues()` is a transparent, inspectable
first pass (see [`docs/confidence-score.md`](confidence-score.md)) rather
than a black-box model, by design — it should be easy to see *why* a patch
lost confidence points.

## Why these specific data sources

| Source | Used for | Why this one |
|---|---|---|
| `registry.npmjs.org` | npm versions | Canonical registry, no auth, full version history + timestamps |
| `pypi.org/pypi/*/json` | PyPI versions | Same — canonical, public, stable JSON API |
| `api.deps.dev` | Maven + NuGet versions | One consistent schema across ecosystems instead of hand-rolling Maven Central XML parsing and the NuGet v3 API separately |
| `security-tracker.debian.org` | Linux/Debian patches + CVEs | The actual authoritative source Debian itself publishes for package ↔ CVE ↔ fixed-version mapping |
| NVD CVE API 2.0 | CVE descriptions, CVSS, CPE matches | The brief explicitly frames this project around NVD's product/patch disconnect — correlating against it directly is the point |
| `endoflife.date` | Lifecycle status | Community-maintained, broad ecosystem coverage, simple JSON API, no auth |

## Running it

See the [README quickstart](../README.md#quickstart). In short:

```bash
docker compose up -d neo4j
pip install -e ".[dev]"
python scripts/seed.py --ecosystem npm --package lodash
uvicorn app.main:app --reload
```
