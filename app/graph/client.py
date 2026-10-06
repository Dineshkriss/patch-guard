from __future__ import annotations

import os
from collections.abc import Iterator
from contextlib import contextmanager

from neo4j import Driver, GraphDatabase, Session

_driver: Driver | None = None


def get_driver() -> Driver:
    """Lazily create a singleton Neo4j driver from env config."""
    global _driver
    if _driver is None:
        uri = os.getenv("NEO4J_URI", "bolt://localhost:7687")
        user = os.getenv("NEO4J_USER", "neo4j")
        password = os.getenv("NEO4J_PASSWORD", "patchguard-dev")
        _driver = GraphDatabase.driver(uri, auth=(user, password))
    return _driver


@contextmanager
def graph_session() -> Iterator[Session]:
    session = get_driver().session()
    try:
        yield session
    finally:
        session.close()


def close_driver() -> None:
    global _driver
    if _driver is not None:
        _driver.close()
        _driver = None
