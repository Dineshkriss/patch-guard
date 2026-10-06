"""Shared deps.dev-backed collection logic, used by the Maven and NuGet
collectors. deps.dev (run by Google/OpenSSF) mirrors Maven Central, NuGet,
npm, PyPI, Go, and Cargo behind one consistent API — no auth required.
"""

from __future__ import annotations

from datetime import datetime

import httpx

from app.models.domain import Ecosystem, Patch

VERSIONS_URL = "https://api.deps.dev/v3/systems/{system}/packages/{name}/versions"


async def collect_versions(
    client: httpx.AsyncClient, system: str, package_name: str, ecosystem: Ecosystem
) -> list[Patch]:
    resp = await client.get(VERSIONS_URL.format(system=system, name=package_name))
    resp.raise_for_status()
    data = resp.json()

    vendor = package_name.split(":")[0] if ":" in package_name else package_name

    patches = []
    for entry in data.get("versions", []):
        version = entry.get("versionKey", {}).get("version")
        if not version:
            continue
        published = entry.get("publishedAt")
        patches.append(
            Patch(
                ecosystem=ecosystem,
                vendor=vendor,
                product=package_name,
                name=package_name,
                fixed_version=version,
                reference_url=f"https://deps.dev/{system.lower()}/{package_name}/{version}",
                released_at=_parse_time(published),
            )
        )
    return patches


def _parse_time(raw: str | None) -> datetime | None:
    if not raw:
        return None
    return datetime.fromisoformat(raw.replace("Z", "+00:00"))
