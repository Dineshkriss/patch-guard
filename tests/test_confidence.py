from datetime import date

from app.models.domain import Ecosystem, IssueCategory, KnownIssue, Patch
from app.scoring.confidence import detect_known_issues, score_patch


def _patch(**overrides) -> Patch:
    defaults = dict(
        ecosystem=Ecosystem.NPM,
        vendor="lodash",
        product="lodash",
        name="lodash",
        fixed_version="4.17.21",
    )
    defaults.update(overrides)
    return Patch(**defaults)


def test_clean_patch_with_verified_fix_scores_100():
    patch = _patch(vulnerabilities_fixed=["CVE-2021-23337"])
    result = score_patch(patch)
    assert result.score == 100
    assert result.breakdown == {"base": 100.0}


def test_known_crash_issue_applies_penalty():
    patch = _patch(
        vulnerabilities_fixed=["CVE-2021-23337"],
        known_issues=[KnownIssue(category=IssueCategory.CRASH, description="crashes on startup")],
    )
    result = score_patch(patch)
    assert result.score == 75
    assert result.breakdown["known_issues"] == -25.0


def test_eol_and_crash_stack():
    patch = _patch(
        vulnerabilities_fixed=["CVE-2021-23337"],
        known_issues=[KnownIssue(category=IssueCategory.CRASH, description="crash")],
        is_eol=True,
        eol_date=date(2020, 1, 1),
    )
    result = score_patch(patch)
    assert result.score == 55


def test_known_issue_penalty_is_capped():
    many_crashes = [
        KnownIssue(category=IssueCategory.CRASH, description=f"crash {i}") for i in range(5)
    ]
    patch = _patch(vulnerabilities_fixed=["CVE-2021-23337"], known_issues=many_crashes)
    result = score_patch(patch)
    assert result.breakdown["known_issues"] == -60.0
    assert result.score == 40


def test_no_verified_fix_penalized():
    patch = _patch(vulnerabilities_fixed=[])
    result = score_patch(patch)
    assert result.score == 85


def test_all_penalties_stack_and_floor_is_never_negative():
    issues = [KnownIssue(category=IssueCategory.CRASH, description=f"crash {i}") for i in range(10)]
    patch = _patch(
        vulnerabilities_fixed=[], known_issues=issues, is_eol=True, eol_date=date(2019, 1, 1)
    )
    result = score_patch(patch)
    # known_issues capped at -60, end_of_life -20, no_verified_cve_fix -15 => 5
    assert result.score == 5
    assert result.score >= 0


def test_detect_known_issues_finds_crash_and_breaking_change():
    issues = detect_known_issues(
        "Fixes a crash on startup. This is a breaking change for plugin authors."
    )
    categories = {issue.category for issue in issues}
    assert IssueCategory.CRASH in categories
    assert IssueCategory.BREAKING_CHANGE in categories


def test_detect_known_issues_empty_for_clean_changelog():
    assert detect_known_issues("Improved docs and added type hints.") == []
