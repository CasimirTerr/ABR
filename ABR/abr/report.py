"""Render a Result as plain text, Markdown or JSON."""

import json
from dataclasses import asdict

from .analyzer import SEVERITIES, tools_without_resources

SCOPE_NOTE = ("ABR checks identity policies only. SCPs, permission boundaries and session policies "
              "can only take permissions away; resource policies (S3 bucket, KMS key) can also grant "
              "access and are not checked.")


def _rating(score):
    if score >= 70:
        return "Severe"
    if score >= 40:
        return "High"
    if score >= 15:
        return "Moderate"
    return "Low"


def _summary_counts(result):
    return ", ".join(f"{result.count(s)} {s.lower()}" for s in SEVERITIES)


def to_text(result, manifest):
    lines = [
        f"ABR blast radius report: {result.agent}",
        "=" * 60,
        f"Blast radius score: {result.score}/100 ({_rating(result.score)})",
        f"Findings: {_summary_counts(result)}",
        f"Risky AWS actions the agent can reach: {len(result.reachable)} "
        f"({len(result.excess_risky)} not used by any tool)",
        "",
    ]
    if not result.findings:
        lines.append("No findings. The role matches what the tools need.")
    for f in result.findings:
        lines.append(f"[{f.severity}] {f.id}  {f.title}")
        for part in f.detail.splitlines():
            lines.append(f"    {part}")
        if f.actions and f.id.startswith("ABR-2"):
            lines.append(f"    Actions: {', '.join(f.actions)}")
        lines.append(f"    Fix: {f.fix}")
        lines.append("")
    loose = tools_without_resources(manifest)
    if loose:
        lines.append(f"Note: these tools list no specific resources, so the generated policy uses "
                     f"Resource '*' for them: {', '.join(loose)}")
    lines.append(SCOPE_NOTE)
    return "\n".join(lines)


def to_markdown(result, manifest):
    lines = [
        f"# ABR blast radius report: `{result.agent}`",
        "",
        f"**Blast radius score:** {result.score}/100 ({_rating(result.score)})  ",
        f"**Findings:** {_summary_counts(result)}  ",
        f"**Risky AWS actions reachable:** {len(result.reachable)} "
        f"({len(result.excess_risky)} not used by any tool)",
        "",
        "| Severity | ID | Finding |",
        "| --- | --- | --- |",
    ]
    for f in result.findings:
        lines.append(f"| {f.severity} | {f.id} | {f.title} |")
    lines.append("")
    for f in result.findings:
        lines += [f"## {f.severity}: {f.title}", "", f.detail, ""]
        if f.actions and f.id.startswith("ABR-2"):
            lines += ["Actions: " + ", ".join(f"`{a}`" for a in f.actions), ""]
        lines += [f"**Fix:** {f.fix}", ""]
    lines += [
        "## Suggested least-privilege policy",
        "",
        "```json",
        json.dumps(result.least_privilege_policy, indent=2),
        "```",
        "",
        f"_{SCOPE_NOTE}_",
    ]
    return "\n".join(lines)


def to_json(result, manifest):
    return json.dumps({
        "agent": result.agent,
        "score": result.score,
        "rating": _rating(result.score),
        "counts": {s.lower(): result.count(s) for s in SEVERITIES},
        "reachable_risky_actions": sorted(result.reachable),
        "unused_risky_actions": result.excess_risky,
        "findings": [asdict(f) for f in result.findings],
        "least_privilege_policy": result.least_privilege_policy,
        "scope_note": SCOPE_NOTE,
    }, indent=2)


RENDERERS = {"text": to_text, "md": to_markdown, "json": to_json}
