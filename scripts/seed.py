#!/usr/bin/env python3
"""CLI entry point for ingesting one package's patch history into the graph.

Usage:
    python scripts/seed.py --ecosystem npm --package lodash
    python scripts/seed.py --ecosystem pypi --package requests --max-versions 10
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import typer

from app.models.domain import Ecosystem
from app.pipeline.ingest import ingest_package

app = typer.Typer(add_completion=False)


@app.command()
def seed(
    ecosystem: Ecosystem = typer.Option(..., "--ecosystem", case_sensitive=False),
    package: str = typer.Option(..., "--package"),
    max_versions: int = typer.Option(15, "--max-versions"),
) -> None:
    """Collect, correlate, score, and load one package's patch history."""
    patches = asyncio.run(ingest_package(ecosystem, package, max_versions=max_versions))
    typer.echo(f"Ingested {len(patches)} patch(es) for {ecosystem.value}:{package}")
    for patch in patches[:5]:
        n_cves = len(patch.vulnerabilities_fixed)
        cve_note = f", fixes {n_cves} CVE(s)" if n_cves else ""
        typer.echo(f"  - {patch.fixed_version}{cve_note}")


if __name__ == "__main__":
    app()
