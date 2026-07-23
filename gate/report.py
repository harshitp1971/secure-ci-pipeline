#!/usr/bin/env python3
"""
Cerberus — Markdown report renderer.

Turns a list of normalised :class:`gate.Finding` objects into a readable
Markdown security report: a severity summary table followed by one section per
tool, each sorted by severity. The gate uses this to drop a report into the CI
logs and to upload as a workflow artifact.

It operates purely on the attributes of a finding (``tool``, ``severity``,
``title``, ``location``, ``rule_id``), so it has no import-time dependency on
gate.py. It can also be run standalone against an ``artifacts/`` directory:

    python gate/report.py --artifacts artifacts --output artifacts/report.md
"""
from __future__ import annotations

import argparse
import os
import sys
from collections import defaultdict
from datetime import datetime, timezone
from typing import Dict, List, Optional

# Local copy of the scale so this module stays importable on its own.
SEVERITY_ORDER: Dict[str, int] = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "info": 0,
}

# Coloured badges render nicely on GitHub while staying readable in plain logs.
SEVERITY_BADGE = {
    "critical": "🔴 CRITICAL",
    "high": "🟠 HIGH",
    "medium": "🟡 MEDIUM",
    "low": "🔵 LOW",
    "info": "⚪ INFO",
}


def _rank(finding) -> int:
    return SEVERITY_ORDER.get(getattr(finding, "severity", ""), -1)


def _escape(text: object) -> str:
    """Escape the handful of characters that would break a Markdown table cell."""
    return str(text).replace("|", "\\|").replace("\n", " ").strip()


def render_markdown(findings: List, policy: Optional[dict] = None) -> str:
    """Render the findings into a Markdown document and return it as a string."""
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    lines: List[str] = []

    lines.append("# 🛡️ Cerberus Security Report")
    lines.append("")
    lines.append(f"_Generated: {generated}_")
    lines.append("")

    # ---- Severity summary -------------------------------------------------
    counts = {sev: 0 for sev in SEVERITY_ORDER}
    for f in findings:
        counts[getattr(f, "severity", "info")] = counts.get(getattr(f, "severity", "info"), 0) + 1

    lines.append("## Summary")
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("| --- | ---: |")
    for sev in SEVERITY_ORDER:  # critical first
        lines.append(f"| {SEVERITY_BADGE[sev]} | {counts[sev]} |")
    lines.append(f"| **Total** | **{len(findings)}** |")
    lines.append("")

    if not findings:
        lines.append("> No findings were reported by any scanner. ✅")
        lines.append("")
        return "\n".join(lines)

    # ---- Per-tool sections ------------------------------------------------
    by_tool: Dict[str, List] = defaultdict(list)
    for f in findings:
        by_tool[getattr(f, "tool", "unknown")].append(f)

    lines.append("## Findings by tool")
    lines.append("")
    for tool in sorted(by_tool):
        tool_findings = sorted(by_tool[tool], key=lambda f: (-_rank(f), getattr(f, "rule_id", "")))
        lines.append(f"### `{tool}` — {len(tool_findings)} finding(s)")
        lines.append("")
        lines.append("| Severity | Rule ID | Title | Location |")
        lines.append("| --- | --- | --- | --- |")
        for f in tool_findings:
            severity = getattr(f, "severity", "info")
            lines.append(
                f"| {SEVERITY_BADGE.get(severity, severity)} "
                f"| `{_escape(getattr(f, 'rule_id', ''))}` "
                f"| {_escape(getattr(f, 'title', ''))} "
                f"| {_escape(getattr(f, 'location', ''))} |"
            )
        lines.append("")

    lines.append("---")
    lines.append("")
    lines.append(
        "_The pass/fail decision is made by `gate.py` against `policy.yml`; "
        "this report lists every normalised finding, including those below the "
        "blocking threshold or accepted via suppression._"
    )
    lines.append("")
    return "\n".join(lines)


def write_report(findings: List, path: str, policy: Optional[dict] = None) -> str:
    """Render the report, write it to `path`, and return the Markdown string."""
    markdown = render_markdown(findings, policy=policy)
    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(markdown)
    return markdown


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Render a Markdown security report from scanner artifacts."
    )
    parser.add_argument("--artifacts", default="artifacts",
                        help="directory containing scanner JSON reports")
    parser.add_argument("--policy",
                        default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "policy.yml"),
                        help="path to the policy YAML file")
    parser.add_argument("--output", default="artifacts/security-report.md",
                        help="path to write the Markdown report to")
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    """Standalone entry point: load artifacts via the gate, then render."""
    args = parse_args(argv)

    # Imported lazily so this module has no import-time dependency on gate.py
    # (and therefore no risk of a circular import).
    from gate import collect_findings, load_policy

    policy = load_policy(args.policy)
    findings, _parsed, _skipped = collect_findings(args.artifacts, policy)
    markdown = write_report(findings, args.output, policy=policy)
    print(markdown)
    print(f"\nReport written to {args.output}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
