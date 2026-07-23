#!/usr/bin/env python3
"""
Cerberus — the centralised security quality gate.

This module is the single decision point of the whole pipeline. Every scanner in
the CI workflow writes its native JSON report into an ``artifacts/`` directory;
this gate then:

    1. Loads the security policy (``policy.yml``).
    2. Reads and parses each scanner report. Missing or malformed files are
       skipped with a warning rather than crashing the build.
    3. Normalises every tool's bespoke output into a single :class:`Finding`
       model that shares one common severity scale.
    4. Applies policy suppressions (accepted risk / triaged false positives).
    5. Decides, per finding, whether its severity is blocking — using the
       per-tool threshold if one is defined, otherwise the global threshold.
    6. Prints a human-readable summary and exits non-zero if any unsuppressed
       finding violates the policy.

Design intent
-------------
Individual scanners are treated as *non-blocking data collectors*: none of them
fails the build on its own. This gate is the one authoritative place where the
"ship / do not ship" decision is made. That keeps security policy centralised,
auditable and version-controlled, instead of being scattered across a dozen CLI
flags in the workflow file.

Usage
-----
    python gate/gate.py --artifacts artifacts --policy gate/policy.yml \\
        --report artifacts/security-report.md

Exit codes: ``0`` = gate passed (deploy may proceed), ``1`` = policy violation.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple

try:
    import yaml
except ImportError:  # pragma: no cover - guidance for a missing runtime dep
    sys.stderr.write(
        "ERROR: PyYAML is required to load the policy file. "
        "Install it with `pip install pyyaml`.\n"
    )
    raise


# ---------------------------------------------------------------------------
# Severity scale
# ---------------------------------------------------------------------------
# The one canonical scale that every tool's vocabulary is mapped onto. The
# integer rank is used purely for sorting and threshold comparisons.
SEVERITY_ORDER: Dict[str, int] = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "info": 0,
}

# Fallback when a tool emits a severity token we do not recognise. "medium" is a
# deliberately cautious middle-ground: unknown findings are neither silently
# dropped nor automatically treated as build-breaking.
DEFAULT_SEVERITY = "medium"


# ---------------------------------------------------------------------------
# Common finding model
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class Finding:
    """A single normalised security finding, independent of the source tool."""

    tool: str          # "semgrep" | "trivy" | "pip-audit" | "zap"
    severity: str      # one of SEVERITY_ORDER keys
    title: str         # short human-readable description
    location: str      # where it is (file:line, package, URL, ...)
    rule_id: str       # stable identifier used for suppressions

    @property
    def rank(self) -> int:
        """Numeric severity, for sorting/comparison (higher = more severe)."""
        return SEVERITY_ORDER.get(self.severity, -1)


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------
def warn(message: str) -> None:
    """Emit a non-fatal warning to stderr (kept visible in CI logs)."""
    sys.stderr.write(f"[gate] WARNING: {message}\n")


def _first_line(text: Optional[str], limit: int = 200) -> str:
    """Return the first line of `text`, trimmed to `limit` characters."""
    if not text:
        return ""
    return str(text).strip().splitlines()[0][:limit]


# ---------------------------------------------------------------------------
# Normalisation layer — one function per tool
# ---------------------------------------------------------------------------
# Each scanner speaks its own severity dialect. The maps below translate those
# dialects onto the shared scale. Every normaliser is written to tolerate empty
# or partially-missing structures so an empty/odd scan result never crashes it.

# Semgrep uses ERROR / WARNING / INFO.
SEMGREP_SEVERITY = {"ERROR": "high", "WARNING": "medium", "INFO": "info"}


def normalize_semgrep(data: object) -> List[Finding]:
    """Normalise a `semgrep --json` document into findings."""
    findings: List[Finding] = []
    results = (data or {}).get("results", []) if isinstance(data, dict) else []
    for r in results or []:
        extra = r.get("extra", {}) or {}
        severity = SEMGREP_SEVERITY.get(
            str(extra.get("severity", "")).upper(), DEFAULT_SEVERITY
        )
        line = (r.get("start", {}) or {}).get("line", "?")
        path = r.get("path", "?")
        findings.append(
            Finding(
                tool="semgrep",
                severity=severity,
                title=_first_line(extra.get("message")) or r.get("check_id", "Semgrep finding"),
                location=f"{path}:{line}",
                rule_id=r.get("check_id", "unknown"),
            )
        )
    return findings


# Trivy (and pip-audit, when it carries a label) use CRITICAL / HIGH / ...
TRIVY_SEVERITY = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
    "UNKNOWN": "info",
}


def normalize_trivy(data: object) -> List[Finding]:
    """Normalise a `trivy ... --format json` document into findings."""
    findings: List[Finding] = []
    results = (data or {}).get("Results", []) if isinstance(data, dict) else []
    for result in results or []:
        target = result.get("Target", "?")

        # OS / language package vulnerabilities.
        for v in result.get("Vulnerabilities", []) or []:
            severity = TRIVY_SEVERITY.get(
                str(v.get("Severity", "")).upper(), DEFAULT_SEVERITY
            )
            pkg = v.get("PkgName", "?")
            installed = v.get("InstalledVersion", "?")
            findings.append(
                Finding(
                    tool="trivy",
                    severity=severity,
                    title=v.get("Title") or v.get("VulnerabilityID") or "Container vulnerability",
                    location=f"{target} -> {pkg}@{installed}",
                    rule_id=v.get("VulnerabilityID", "unknown"),
                )
            )

        # Dockerfile / IaC misconfigurations, if the scan produced any.
        for m in result.get("Misconfigurations", []) or []:
            severity = TRIVY_SEVERITY.get(
                str(m.get("Severity", "")).upper(), DEFAULT_SEVERITY
            )
            findings.append(
                Finding(
                    tool="trivy",
                    severity=severity,
                    title=m.get("Title") or m.get("ID") or "Misconfiguration",
                    location=str(target),
                    rule_id=m.get("ID", "unknown"),
                )
            )
    return findings


# pip-audit's default JSON does NOT carry a severity, so we fall back to a
# configurable default (policy: tools.pip-audit.default_severity). If an OSV
# label happens to be present we honour it via this map.
PIP_AUDIT_SEVERITY = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "MODERATE": "medium",
    "LOW": "low",
    "INFO": "info",
    "NONE": "info",
}


def _pip_audit_severity(vuln: dict, default: str) -> str:
    """Resolve a pip-audit vuln's severity, falling back to `default`.

    pip-audit's schema does not guarantee a severity field. Some records carry a
    plain label; OSV records instead carry a list of CVSS vectors that we do not
    fully parse here. When no simple label is available we return `default`
    (conservatively "high" by policy) — a known-vulnerable dependency is treated
    as blocking unless the policy says otherwise.
    """
    label = vuln.get("severity")
    if isinstance(label, str) and label:
        return PIP_AUDIT_SEVERITY.get(label.upper(), default)
    return default


def normalize_pip_audit(data: object, default_severity: str = "high") -> List[Finding]:
    """Normalise a `pip-audit --format json` document into findings."""
    findings: List[Finding] = []

    # pip-audit emits either {"dependencies": [...]} (newer) or a bare list.
    if isinstance(data, dict):
        deps = data.get("dependencies", []) or []
    elif isinstance(data, list):
        deps = data
    else:
        deps = []

    for dep in deps:
        name = dep.get("name", "?")
        version = dep.get("version", "?")
        for vuln in dep.get("vulns", []) or []:
            severity = _pip_audit_severity(vuln, default_severity)
            aliases = vuln.get("aliases", []) or []
            # Prefer a recognisable CVE id for the rule_id (used in suppressions).
            rule_id = next(
                (a for a in aliases if str(a).startswith("CVE-")),
                vuln.get("id", "unknown"),
            )
            fix = ", ".join(vuln.get("fix_versions", []) or []) or "no fix listed"
            findings.append(
                Finding(
                    tool="pip-audit",
                    severity=severity,
                    title=_first_line(vuln.get("description")) or vuln.get("id", "Vulnerable dependency"),
                    location=f"{name}=={version} (fix: {fix})",
                    rule_id=rule_id,
                )
            )
    return findings


# OWASP ZAP uses a numeric riskcode: 3=High, 2=Medium, 1=Low, 0=Info.
ZAP_RISKCODE = {3: "high", 2: "medium", 1: "low", 0: "info"}


def normalize_zap(data: object) -> List[Finding]:
    """Normalise a ZAP baseline JSON report into findings."""
    findings: List[Finding] = []
    sites = (data or {}).get("site", []) if isinstance(data, dict) else []
    for site in sites or []:
        site_name = site.get("@name", "?")
        for alert in site.get("alerts", []) or []:
            try:
                risk = int(alert.get("riskcode", 0))
            except (TypeError, ValueError):
                risk = 0
            severity = ZAP_RISKCODE.get(risk, "info")
            instances = alert.get("instances", []) or []
            uri = instances[0].get("uri") if instances else None
            findings.append(
                Finding(
                    tool="zap",
                    severity=severity,
                    title=alert.get("alert") or alert.get("name") or "ZAP alert",
                    location=uri or site_name,
                    rule_id=str(alert.get("pluginid", "unknown")),
                )
            )
    return findings


# Registry mapping each tool to its artifact filename and normaliser. Adding a
# new scanner is as simple as writing a normaliser and adding one line here.
Normalizer = Callable[..., List[Finding]]
SCANNERS: Dict[str, Tuple[str, Normalizer]] = {
    "semgrep": ("semgrep.json", normalize_semgrep),
    "pip-audit": ("pip-audit.json", normalize_pip_audit),
    "trivy": ("trivy.json", normalize_trivy),
    "zap": ("zap.json", normalize_zap),
}


# ---------------------------------------------------------------------------
# Loading (graceful about missing / malformed input)
# ---------------------------------------------------------------------------
def load_json(path: str) -> Optional[object]:
    """Load a JSON file, returning ``None`` (with a warning) on any problem."""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except FileNotFoundError:
        warn(f"scan report not found: {path} (skipping)")
    except (json.JSONDecodeError, OSError) as exc:
        warn(f"could not parse {path}: {exc} (skipping)")
    return None


def collect_findings(
    artifacts_dir: str, policy: dict
) -> Tuple[List[Finding], List[str], List[str]]:
    """Read and normalise every scanner report found in `artifacts_dir`.

    Returns a tuple of ``(findings, parsed_tools, skipped_tools)`` so callers can
    report which scanners actually contributed data.
    """
    findings: List[Finding] = []
    parsed: List[str] = []
    skipped: List[str] = []

    pip_default = _tool_cfg(policy, "pip-audit").get("default_severity", "high")

    for tool, (filename, normalizer) in SCANNERS.items():
        path = os.path.join(artifacts_dir, filename)
        data = load_json(path)
        if data is None:
            skipped.append(tool)
            continue
        try:
            if tool == "pip-audit":
                tool_findings = normalizer(data, default_severity=pip_default)
            else:
                tool_findings = normalizer(data)
        except Exception as exc:  # never let one odd structure crash the gate
            warn(f"normaliser for {tool} failed: {exc} (skipping {tool})")
            skipped.append(tool)
            continue
        findings.extend(tool_findings)
        parsed.append(tool)

    return findings, parsed, skipped


# ---------------------------------------------------------------------------
# Policy
# ---------------------------------------------------------------------------
# Safe defaults used when policy.yml is missing or unreadable: fail closed on
# high and critical, no per-tool overrides, no suppressions.
DEFAULT_POLICY: Dict[str, object] = {
    "block_on": ["high", "critical"],
    "tools": {},
    "suppressions": [],
}


def load_policy(path: str) -> dict:
    """Load and validate policy.yml, merging onto safe defaults."""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
    except FileNotFoundError:
        warn(f"policy file not found: {path} — using safe defaults (block on high, critical)")
        return dict(DEFAULT_POLICY)
    except yaml.YAMLError as exc:
        warn(f"could not parse policy {path}: {exc} — using safe defaults")
        return dict(DEFAULT_POLICY)

    policy = dict(DEFAULT_POLICY)
    if isinstance(data, dict):
        for key, value in data.items():
            if value is not None:
                policy[key] = value
    # Guarantee the core keys are always present and of the right shape.
    policy.setdefault("block_on", DEFAULT_POLICY["block_on"])
    policy.setdefault("tools", {})
    policy.setdefault("suppressions", [])
    return policy


def _tool_cfg(policy: dict, tool: str) -> dict:
    """Return the per-tool config block for `tool` (empty dict if absent)."""
    return (policy.get("tools") or {}).get(tool, {}) or {}


def blocking_severities_for(policy: dict, tool: str) -> set:
    """Resolve the set of blocking severities for a tool.

    Uses the per-tool ``block_on`` if defined, otherwise the global ``block_on``.
    """
    raw = _tool_cfg(policy, tool).get("block_on", policy.get("block_on", []))
    return {str(s).lower() for s in (raw or [])}


def build_suppression_index(policy: dict) -> Dict[str, str]:
    """Build a ``key -> reason`` index from the policy's suppression list.

    A suppression may be global (matched by ``rule_id`` across all tools) or
    scoped to a single tool (via an optional ``tool`` field). Scoped entries use
    a ``"<tool>:<rule_id>"`` key so they only match that tool's findings.
    """
    index: Dict[str, str] = {}
    for entry in policy.get("suppressions", []) or []:
        if not isinstance(entry, dict):
            continue
        rule_id = entry.get("rule_id")
        if not rule_id:
            warn("suppression entry without a rule_id was ignored")
            continue
        reason = entry.get("reason", "(no reason given)")
        tool = entry.get("tool")
        key = f"{tool}:{rule_id}" if tool else str(rule_id)
        index[key] = reason
    return index


def suppression_for(finding: Finding, index: Dict[str, str]) -> Optional[str]:
    """Return the suppression reason for a finding, or ``None`` if not suppressed.

    A tool-scoped suppression takes precedence over a global one.
    """
    return index.get(f"{finding.tool}:{finding.rule_id}") or index.get(finding.rule_id)


# ---------------------------------------------------------------------------
# Evaluation
# ---------------------------------------------------------------------------
@dataclass
class GateResult:
    """The outcome of evaluating all findings against the policy."""

    findings: List[Finding]
    violations: List[Finding]
    suppressed: List[Tuple[Finding, str]]
    parsed_tools: List[str] = field(default_factory=list)
    skipped_tools: List[str] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return not self.violations


def evaluate(
    findings: List[Finding],
    policy: dict,
    parsed: Optional[List[str]] = None,
    skipped: Optional[List[str]] = None,
) -> GateResult:
    """Apply suppressions and per-tool/global thresholds to classify findings."""
    suppression_index = build_suppression_index(policy)
    violations: List[Finding] = []
    suppressed: List[Tuple[Finding, str]] = []

    for finding in findings:
        reason = suppression_for(finding, suppression_index)
        if reason is not None:
            suppressed.append((finding, reason))
            continue
        if finding.severity in blocking_severities_for(policy, finding.tool):
            violations.append(finding)

    # Most severe first, then stable by tool + rule for readable output.
    violations.sort(key=lambda f: (-f.rank, f.tool, f.rule_id))

    return GateResult(
        findings=findings,
        violations=violations,
        suppressed=suppressed,
        parsed_tools=parsed or [],
        skipped_tools=skipped or [],
    )


# ---------------------------------------------------------------------------
# Summary output
# ---------------------------------------------------------------------------
def _counts_by_severity(findings: List[Finding]) -> Dict[str, int]:
    counts = {sev: 0 for sev in SEVERITY_ORDER}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    return counts


def print_summary(result: GateResult, policy: dict) -> None:
    """Print a clear, CI-friendly summary of the gate evaluation."""
    line = "=" * 68
    print(line)
    print("  CERBERUS SECURITY QUALITY GATE")
    print(line)

    # Which scanners contributed data.
    print(f"  Scanners parsed : {', '.join(result.parsed_tools) or 'none'}")
    if result.skipped_tools:
        print(f"  Scanners skipped: {', '.join(result.skipped_tools)} (missing/unreadable)")

    # Totals by severity across every finding.
    counts = _counts_by_severity(result.findings)
    totals = "  ".join(f"{sev.upper()}={counts[sev]}" for sev in SEVERITY_ORDER)
    print(f"  Findings        : {len(result.findings)} total  ->  {totals}")
    print(f"  Suppressed      : {len(result.suppressed)}")
    print(line)

    # Suppressed findings (accepted risk / false positives) for transparency.
    if result.suppressed:
        print("  SUPPRESSED (policy-accepted):")
        for finding, reason in result.suppressed:
            print(f"    - [{finding.tool}] {finding.rule_id}  {finding.title}")
            print(f"        reason: {reason}")
        print(line)

    # The findings that actually breach the policy.
    if result.violations:
        print(f"  POLICY VIOLATIONS ({len(result.violations)}):")
        for f in result.violations:
            print(f"    [{f.severity.upper():<8}] {f.tool:<9} {f.rule_id}")
            print(f"               {f.title}")
            print(f"               at {f.location}")
    else:
        print("  No policy violations.")
    print(line)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Cerberus — centralised security quality gate."
    )
    parser.add_argument(
        "--artifacts",
        default="artifacts",
        help="directory containing scanner JSON reports (default: artifacts)",
    )
    parser.add_argument(
        "--policy",
        default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "policy.yml"),
        help="path to the policy YAML file (default: gate/policy.yml)",
    )
    parser.add_argument(
        "--report",
        default=None,
        help="optional path to also write a Markdown report",
    )
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    """Run the gate. Returns the intended process exit code."""
    args = parse_args(argv)

    policy = load_policy(args.policy)
    findings, parsed, skipped = collect_findings(args.artifacts, policy)
    result = evaluate(findings, policy, parsed, skipped)

    print_summary(result, policy)

    if args.report:
        # Imported lazily so gate.py has no hard dependency on report.py.
        import report

        report.write_report(result.findings, args.report, policy=policy)
        print(f"Markdown report written to {args.report}")

    if result.violations:
        print(
            f"\nGATE FAILED: {len(result.violations)} policy violation(s) "
            "block deployment."
        )
        return 1

    print("\nGATE PASSED: no policy violations. Deployment may proceed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
