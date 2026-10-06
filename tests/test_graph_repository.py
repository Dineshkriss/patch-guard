from unittest.mock import MagicMock

from app.graph import repository
from app.models.domain import CVE, Ecosystem, Patch


def test_upsert_cve_runs_merge_with_expected_params():
    session = MagicMock()
    cve = CVE(cve_id="CVE-2021-23337", description="desc", cvss_score=7.2, cvss_severity="HIGH")

    repository.upsert_cve(session, cve)

    query, kwargs = session.run.call_args[0][0], session.run.call_args[1]
    assert "MERGE (c:CVE" in query
    assert kwargs["cve_id"] == "CVE-2021-23337"
    assert kwargs["cvss_severity"] == "HIGH"


def test_upsert_patch_serializes_patch_id_and_score():
    session = MagicMock()
    patch = Patch(
        ecosystem=Ecosystem.NPM,
        vendor="lodash",
        product="lodash",
        name="lodash",
        fixed_version="4.17.21",
    )

    repository.upsert_patch(session, patch, confidence_score=92)

    kwargs = session.run.call_args[1]
    assert kwargs["patch_id"] == "npm:lodash:4.17.21"
    assert kwargs["confidence_score"] == 92
    assert kwargs["ecosystem"] == "npm"


def test_link_patch_fixes_cve_matches_both_nodes():
    session = MagicMock()
    repository.link_patch_fixes_cve(session, "npm:lodash:4.17.21", "CVE-2021-23337")

    query, kwargs = session.run.call_args[0][0], session.run.call_args[1]
    assert "FIXES" in query
    assert kwargs["patch_id"] == "npm:lodash:4.17.21"
    assert kwargs["cve_id"] == "CVE-2021-23337"


def test_get_patch_returns_none_when_not_found():
    session = MagicMock()
    session.run.return_value.single.return_value = None

    assert repository.get_patch(session, "npm:missing:1.0.0") is None
