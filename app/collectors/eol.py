"""End-of-life lookups via endoflife.date — https://endoflife.date/api.

Fills the "End of Lifecycle Information" risk signal called out in the
project brief: a patch to a release line that's already EOL is a different
decision than one that still has vendor support.
"""

from __future__ import annotations

from datetime import date, datetime

import httpx

EOL_API_URL = "https://endoflife.date/api/{product}.json"


async def get_eol_status(client: httpx.AsyncClient, product: str, cycle: str) -> tuple[bool, date | None]:
    """Whether a given release cycle (e.g. "3.11", "20.04") of a product
    tracked by endoflife.date has reached end-of-life.

    Returns (is_eol, eol_date). Untracked products/cycles return (False,
    None) rather than raising — EOL is a bonus signal, not a hard dependency.
    """
    try:
        resp = await client.get(EOL_API_URL.format(product=product))
        resp.raise_for_status()
    except httpx.HTTPError:
        return False, None

    for entry in resp.json():
        if str(entry.get("cycle")) == cycle:
            eol_date = _parse_eol(entry.get("eol"))
            if eol_date is None:
                return False, None
            return eol_date <= date.today(), eol_date
    return False, None


def _parse_eol(raw: object) -> date | None:
    if not isinstance(raw, str):
        return None
    try:
        return datetime.fromisoformat(raw).date()
    except ValueError:
        return None
