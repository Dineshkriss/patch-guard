from __future__ import annotations

from typing import Protocol

import httpx

from app.models.domain import Patch

DEFAULT_TIMEOUT = httpx.Timeout(15.0)
USER_AGENT = "patch-guard/0.1 (+https://github.com/Dineshkriss/patch-guard)"


def new_http_client(**kwargs) -> httpx.AsyncClient:
    return httpx.AsyncClient(timeout=DEFAULT_TIMEOUT, headers={"User-Agent": USER_AGENT}, **kwargs)


class Collector(Protocol):
    """An ecosystem collector turns a package name into a list of candidate patches."""

    async def collect(self, client: httpx.AsyncClient, package_name: str) -> list[Patch]: ...
