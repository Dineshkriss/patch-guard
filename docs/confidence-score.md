# Confidence score

The problem brief this project is built around calls out a specific gap:
there's no structured signal on patch *safety* — known issues, crash
likelihood, reboot requirements, EOL status — so teams can't make a
confident apply/hold decision. This document is that signal's formula.

## It's a safety score, not a severity score

Two different questions come up when a patch lands:

- **Urgency** — how bad is the vulnerability it fixes? (CVSS answers this.)
- **Confidence** — how safe is it to actually roll this patch out?

Patch Guard deliberately keeps these separate. A patch for a critical CVE
can still have a *low* confidence score if it's known to crash the service
or force a reboot — that's useful information, not a contradiction. The
confidence score only answers the second question.

## The formula

Every patch starts at **100** and loses points for operational risk
signals, implemented in [`app/scoring/confidence.py`](../app/scoring/confidence.py):

| Signal | Penalty | Why |
|---|---|---|
| Known crash issue | -25 (per category, capped) | Directly operationally destructive |
| Breaking change | -15 | Forces downstream code/config changes |
| Performance regression | -10 | Degrades the system it's meant to protect |
| Reboot required | -10 | Scheduling/availability cost |
| Other known issue | -5 | Catch-all for anything flagged but uncategorized |
| *(cap on combined known-issue penalty)* | -60 max | One catastrophic patch shouldn't look identical to "never apply this" |
| Target is end-of-life | -20 | No further vendor support if something goes wrong |
| No verified CVE correlation yet | -15 | We can't yet confirm what this patch actually fixes |

The final score is clamped to `[0, 100]`.

## Where the signals come from

- **Known issues** are detected from changelog/release-note text via a
  keyword heuristic (`detect_known_issues` in the same module) — looking
  for terms like "crash", "segfault", "breaking change", "restart required".
  This mirrors how the brief describes sourcing this data: "vendor
  disclosures, open source, forums etc." There's no clean structured feed
  for this across ecosystems, so a transparent heuristic beats a opaque one.
- **EOL status** comes from the `endoflife.date` API (`app/collectors/eol.py`).
- **CVE correlation** comes from the NVD CVE API (`app/collectors/nvd.py`).

## Example

A Debian patch with no known issues, not EOL, that fixes two CVEs:

```
base               100
                   ────
                   100  → clamped to 100
```

The same patch, but changelog mentions "may crash on startup" and the
target release is EOL:

```
base               100
known_issues       -25
end_of_life        -20
                   ────
                    55
```
