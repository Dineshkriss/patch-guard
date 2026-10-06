"""Collector for the npm registry — https://registry.npmjs.org."""

from __future__ import annotations

from datetime import datetime

import httpx

from app.models.domain import Ecosystem, Patch

REGISTRY_URL = "https://registry.npmjs.org/{name}"


async def collect(client: httpx.AsyncClient, package_name: str) -> list[Patch]:
    """Every published version of an npm package, treated as a candidate patch."""
    resp = await client.get(REGISTRY_URL.format(name=package_name))
    resp.raise_for_status()
    data = resp.json()

    times: dict[str, str] = data.get("time", {})
    versions: dict[str, dict] = data.get("versions", {})
    is_scoped = package_name.startswith("@")
    vendor = package_name.lstrip("@").split("/")[0] if is_scoped else package_name

    patches = []
    for version in versions:
        released_raw = times.get(version)
        patches.append(
            Patch(
                ecosystem=Ecosystem.NPM,
                vendor=vendor,
                product=package_name,
                name=package_name,
                fixed_version=version,
                reference_url=f"https://www.npmjs.com/package/{package_name}/v/{version}",
                released_at=_parse_time(released_raw),
            )
        )
    return patches


def _parse_time(raw: str | None) -> datetime | None:
    if not raw:
        return None
    return datetime.fromisoformat(raw.replace("Z", "+00:00"))
