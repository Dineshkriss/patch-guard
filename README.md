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

## Tech stack

Python · FastAPI · Neo4j · httpx · Pydantic · Docker Compose · GitHub Actions

## Project status

| Milestone | Status |
|---|---|
| Collection (npm/PyPI/Maven/NuGet/Linux) | In progress |
| Correlation (CVE/CPE via NVD) | In progress |
| Confidence scoring | In progress |
| Knowledge graph (Neo4j) | In progress |
| API | In progress |
| Automation (scheduled refresh) | In progress |

## License

MIT — see [LICENSE](LICENSE).
