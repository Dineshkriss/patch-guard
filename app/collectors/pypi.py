"""Collector for the Python Package Index — https://pypi.org."""

from __future__ import annotations

from datetime import datetime

import httpx

from app.models.domain import Ecosystem, Patch

PYPI_URL = "https://pypi.org/pypi/{name}/json"


async def collect(client: httpx.AsyncClient, package_name: str) -> list[Patch]:
    """Every released version of a PyPI package, treated as a candidate patch."""
    resp = await client.get(PYPI_URL.format(name=package_name))
    resp.raise_for_status()
    data = resp.json()

    releases: dict[str, list[dict]] = data.get("releases", {})

    patches = []
    for version, files in releases.items():
        if not files:
            continue
        upload_time = files[0].get("upload_time_iso_8601")
        patches.append(
            Patch(
                ecosystem=Ecosystem.PYPI,
                vendor=package_name,
                product=package_name,
                name=package_name,
                fixed_version=version,
                reference_url=f"https://pypi.org/project/{package_name}/{version}/",
                released_at=_parse_time(upload_time),
            )
        )
    return patches


def _parse_time(raw: str | None) -> datetime | None:
    if not raw:
        return None
    return datetime.fromisoformat(raw.replace("Z", "+00:00"))
