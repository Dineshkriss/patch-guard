from __future__ import annotations

from fastapi import APIRouter, HTTPException

from app.graph.client import graph_session
from app.graph.repository import get_package_patches
from app.models.domain import Ecosystem

router = APIRouter(prefix="/packages", tags=["packages"])


@router.get("/{ecosystem}/{name}")
def list_package_patches(ecosystem: Ecosystem, name: str) -> dict:
    """All known patches for a package, ranked by confidence score where available."""
    with graph_session() as session:
        rows = get_package_patches(session, ecosystem.value, name)

    if not rows:
        raise HTTPException(
            status_code=404, detail=f"No ingested patches for {ecosystem.value}:{name}"
        )

    return {
        "ecosystem": ecosystem.value,
        "name": name,
        "patches": [dict(row["patch"]) for row in rows],
    }
