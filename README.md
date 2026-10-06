# Patch Guard

A live patch intelligence knowledge graph. Patch Guard collects real patch data
for major package ecosystems, correlates it against CVEs and CPEs, and computes
a **confidence score** for every patch so a team can answer the question that
most vulnerability tooling leaves unanswered: *if I apply this patch, what am I
actually signing up for?*

## The problem

Vulnerability management tells you *what* is vulnerable. It rarely tells you
*what to do about it*. Two gaps show up in almost every patch management
workflow:

1. **Vulnerability data and patch data live in disconnected systems.** NVD and
   MITRE advisories mostly link out to vendor pages, not to the actual fixed
   package version — so "which version do I need" becomes manual research.
2. **There's no operational signal on the patch itself.** Known issues, crash
   likelihood, reboot requirements, end-of-life status — none of that is
   captured anywhere a team can query it before deciding to roll a patch out.

Patch Guard addresses both by building a bidirectional knowledge graph:

```
CVE ──────▶ CPE ──────▶ Patch
 ▲             ▲            │
 └── fixed in ─┴── vendor/product/version ──┘
                             │
                 confidence score (0-100)
```

## What it does

- **Collects** real patch metadata for `npm`, `PyPI`, `Maven`, `NuGet`, and
  `Linux` (Debian) packages from live public registries — no static CSVs.
- **Correlates** that data against the NVD CVE API (CVE ↔ CPE ↔ fixed version)
  and `endoflife.date` (lifecycle status).
- **Scores** every patch on a 0-100 confidence scale, combining whether a fix
  exists, the severity of what it fixes, and operational risk signals pulled
  from changelogs (crash/regression keywords, reboot requirements, EOL
  proximity). See [`docs/confidence-score.md`](docs/confidence-score.md).
- **Stores** everything in Neo4j as a real, queryable graph — not a SQL table
  pretending to be one.
- **Serves** it over a FastAPI REST API with interactive OpenAPI docs.
- **Refreshes** itself on a schedule via GitHub Actions.

## Architecture

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the full breakdown.
Short version:

```
collectors/  → raw data from npm / PyPI / deps.dev / Debian / NVD / endoflife.date
scoring/     → confidence score engine
pipeline/    → orchestrates collect → correlate → score → graph upsert
graph/       → Neo4j client + repository (Cypher)
api/         → FastAPI routes over the graph
```

## Quickstart

```bash
git clone https://github.com/Dineshkriss/patch-guard.git
cd patch-guard
cp .env.example .env

# start Neo4j
docker compose up -d neo4j

# install deps
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

# seed the graph with a real package
python scripts/seed.py --ecosystem npm --package lodash

# run the API
uvicorn app.main:app --reload
# → http://localhost:8000/docs
```

### Example output

```
$ python scripts/seed.py --ecosystem npm --package lodash --max-versions 10
Ingested 10 patch(es) for npm:lodash
  - 4.18.1, fixes 9 CVE(s)
  - 4.18.0, fixes 9 CVE(s)
  - 4.17.23, fixes 9 CVE(s)
  - 4.17.21, fixes 9 CVE(s)
  - 4.17.20, fixes 9 CVE(s)

$ curl localhost:8000/graph/CVE-2021-23337
{
  "cve_id": "CVE-2021-23337",
  "patches": [
    {
      "patch": {
        "patch_id": "npm:lodash:4.17.15",
        "ecosystem": "npm",
        "fixed_version": "4.17.15",
        "confidence_score": 100,
        "is_eol": false
      },
      "cpe": {
        "cpe23uri": "cpe:2.3:a:lodash:lodash:*:*:*:*:*:node.js:*:*"
      }
    }
  ]
}
```

That's a real `MATCH (cve:CVE {cve_id: $cve_id})<-[:FIXES]-(patch:Patch)-[:APPLIES_TO]->(cpe:CPE)`
traversal, run against a Neo4j instance seeded two minutes earlier from
live npm + NVD data — not a fixture.

## Tech stack

Python · FastAPI · Neo4j · httpx · Pydantic · Docker Compose · GitHub Actions

## Project status

| Milestone | Status |
|---|---|
| Collection (npm/PyPI/Maven/NuGet/Linux) | Done — live registries, no static CSVs |
| Correlation (CVE/CPE via NVD) | Done — product-name match; see [known limitations](docs/ARCHITECTURE.md#design-decisions-and-known-limitations) |
| Confidence scoring | Done — see [docs/confidence-score.md](docs/confidence-score.md) |
| Knowledge graph (Neo4j) | Done |
| REST API | Done |
| Automation (scheduled refresh) | Done — weekly GitHub Actions cron |
| Precise version-range correlation | Planned |
| Web dashboard / graph visualization | Planned |

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for design decisions and
what's deliberately simplified in this pass.

## License

MIT — see [LICENSE](LICENSE).
