"""Collector for Maven Central, via the deps.dev API."""

from __future__ import annotations

import httpx

from app.collectors.depsdev import collect_versions
from app.models.domain import Ecosystem, Patch


async def collect(client: httpx.AsyncClient, package_name: str) -> list[Patch]:
    """`package_name` is `group:artifact`, e.g. `com.fasterxml.jackson.core:jackson-databind`."""
    return await collect_versions(client, "MAVEN", package_name, Ecosystem.MAVEN)
