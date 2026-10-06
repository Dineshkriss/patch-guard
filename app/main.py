from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.api.routes import graph, health, packages, patches
from app.graph.client import close_driver, graph_session
from app.graph.schema import apply_schema


@asynccontextmanager
async def lifespan(app: FastAPI):
    with graph_session() as session:
        apply_schema(session)
    yield
    close_driver()


def create_app() -> FastAPI:
    fastapi_app = FastAPI(
        title="Patch Guard",
        description=(
            "A live patch intelligence knowledge graph: CVE <-> CPE <-> Patch "
            "correlation with a transparent confidence score for patch decisions."
        ),
        version="0.1.0",
        lifespan=lifespan,
    )
    fastapi_app.include_router(health.router)
    fastapi_app.include_router(packages.router)
    fastapi_app.include_router(patches.router)
    fastapi_app.include_router(graph.router)
    return fastapi_app


app = create_app()
