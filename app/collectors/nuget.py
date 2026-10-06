"""Collector for NuGet, via the deps.dev API."""

from __future__ import annotations

import httpx

from app.collectors.depsdev import collect_versions
from app.models.domain import Ecosystem, Patch


async def collect(client: httpx.AsyncClient, package_name: str) -> list[Patch]:
    return await collect_versions(client, "NUGET", package_name, Ecosystem.NUGET)
