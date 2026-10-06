from __future__ import annotations

from fastapi import APIRouter, HTTPException

from app.graph.client import graph_session
from app.graph.repository import get_patch_neighborhood

router = APIRouter(prefix="/graph", tags=["graph"])


@router.get("/{cve_id}")
def get_cve_neighborhood(cve_id: str) -> dict:
    """Every patch that fixes this CVE, with the CPE it applies to — the core
    "what do I do about this vulnerability" query the project exists to answer.
    """
    with graph_session() as session:
        rows = get_patch_neighborhood(session, cve_id)

    if not rows:
        raise HTTPException(status_code=404, detail=f"No patches found fixing {cve_id}")

    return {
        "cve_id": cve_id,
        "patches": [{"patch": dict(row["patch"]), "cpe": dict(row["cpe"])} for row in rows],
    }
