"""Collector for Debian/Linux packages, via the Debian Security Tracker.

The tracker publishes one large JSON feed keyed by source package name
(https://security-tracker.debian.org/tracker/data/json) rather than a
per-package endpoint, so we fetch it once per run and filter it down. Each
distinct (release, fixed_version) pair becomes a patch, aggregating every
CVE it fixes.
"""

from __future__ import annotations

import httpx

from app.models.domain import Ecosystem, Patch

SECURITY_TRACKER_URL = "https://security-tracker.debian.org/tracker/data/json"
FETCH_TIMEOUT = httpx.Timeout(60.0)


async def collect(client: httpx.AsyncClient, package_name: str) -> list[Patch]:
    resp = await client.get(SECURITY_TRACKER_URL, timeout=FETCH_TIMEOUT)
    resp.raise_for_status()
    data = resp.json()

    package_data = data.get(package_name)
    if not package_data:
        return []

    patches: dict[str, Patch] = {}
    for cve_id, cve_info in package_data.items():
        for release, release_info in cve_info.get("releases", {}).items():
            fixed_version = release_info.get("fixed_version")
            if not fixed_version or fixed_version == "0":
                continue
            patch_key = f"{release}:{fixed_version}"
            patch = patches.get(patch_key)
            if patch is None:
                patch = Patch(
                    ecosystem=Ecosystem.LINUX,
                    vendor="debian",
                    product=package_name,
                    name=f"{package_name} ({release})",
                    fixed_version=fixed_version,
                    reference_url=(
                        f"https://security-tracker.debian.org/tracker/source-package/{package_name}"
                    ),
                )
                patches[patch_key] = patch
            patch.vulnerabilities_fixed.append(cve_id)

    return list(patches.values())
