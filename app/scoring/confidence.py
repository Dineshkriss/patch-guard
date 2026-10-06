"""The patch confidence scoring engine.

This is the piece the project brief asks for and the reference
implementation never actually built: a transparent, reproducible score for
"how safe is it to apply this patch", independent of how urgent the CVE it
fixes is. See docs/confidence-score.md for the full rationale.
"""

from __future__ import annotations

from datetime import UTC, datetime

from app.models.domain import ConfidenceScore, IssueCategory, KnownIssue, Patch

BASE_SCORE = 100.0

CATEGORY_PENALTIES: dict[IssueCategory, float] = {
    IssueCategory.CRASH: 25.0,
    IssueCategory.BREAKING_CHANGE: 15.0,
    IssueCategory.PERFORMANCE: 10.0,
    IssueCategory.REBOOT_REQUIRED: 10.0,
    IssueCategory.OTHER: 5.0,
}
MAX_KNOWN_ISSUE_PENALTY = 60.0
EOL_PENALTY = 20.0
UNVERIFIED_FIX_PENALTY = 15.0


def score_patch(patch: Patch) -> ConfidenceScore:
    """Score how safe `patch` is to apply, on a 0-100 scale.

    Deliberately NOT a severity/urgency score: a patch fixing a critical CVE
    can still score low here if it's known to be operationally risky.
    Urgency (how bad is the CVE) and confidence (how safe is the fix) are
    kept as separate axes so a team can reason about both independently.
    """
    breakdown: dict[str, float] = {"base": BASE_SCORE}

    known_issue_penalty = min(
        sum(CATEGORY_PENALTIES.get(issue.category, 5.0) for issue in patch.known_issues),
        MAX_KNOWN_ISSUE_PENALTY,
    )
    if known_issue_penalty:
        breakdown["known_issues"] = -known_issue_penalty

    if patch.is_eol:
        breakdown["end_of_life"] = -EOL_PENALTY

    if not patch.vulnerabilities_fixed:
        breakdown["no_verified_cve_fix"] = -UNVERIFIED_FIX_PENALTY

    raw_score = sum(breakdown.values())
    clamped_score = max(0, min(100, round(raw_score)))

    return ConfidenceScore(
        patch_id=patch.patch_id,
        score=clamped_score,
        breakdown=breakdown,
        computed_at=datetime.now(UTC),
    )


_KEYWORD_CATEGORIES: list[tuple[IssueCategory, tuple[str, ...]]] = [
    (IssueCategory.CRASH, ("crash", "segfault", "panic", "fatal error")),
    (IssueCategory.REBOOT_REQUIRED, ("reboot required", "requires a restart", "restart required")),
    (IssueCategory.BREAKING_CHANGE, ("breaking change", "breaking:", "backwards incompatible")),
    (IssueCategory.PERFORMANCE, ("regression", "performance degradation", "slowdown")),
]


def detect_known_issues(text: str, source_url: str | None = None) -> list[KnownIssue]:
    """Keyword heuristic for pulling risk signals out of changelog/release-
    note text when no structured vendor disclosure exists. One hit per
    category is enough signal to flag it — this stays a coarse heuristic by
    design, not a classifier.
    """
    lowered = text.lower()
    issues: list[KnownIssue] = []
    for category, keywords in _KEYWORD_CATEGORIES:
        for keyword in keywords:
            if keyword in lowered:
                issues.append(
                    KnownIssue(
                        category=category,
                        description=f"Changelog mentions '{keyword}'",
                        source_url=source_url,
                    )
                )
                break
    return issues
