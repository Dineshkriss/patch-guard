from __future__ import annotations

from fastapi import APIRouter, HTTPException

from app.graph.client import graph_session
from app.graph.repository import get_patch
from app.models.domain import Ecosystem

router = APIRouter(prefix="/patches", tags=["patches"])


@router.get("/{ecosystem}/{product}/{version}")
def get_patch_detail(ecosystem: Ecosystem, product: str, version: str) -> dict:
    """Single patch detail, including its computed confidence score."""
    patch_id = f"{ecosystem.value}:{product}:{version}"
    with graph_session() as session:
        patch = get_patch(session, patch_id)

    if patch is None:
        raise HTTPException(status_code=404, detail=f"No patch found for {patch_id}")
    return patch
