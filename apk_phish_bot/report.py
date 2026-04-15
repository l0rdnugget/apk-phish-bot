"""Render ApkReport / Diff / RiskAssessment into Markdown and JSON."""

from __future__ import annotations

import json
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from typing import Optional

from .analyzer import ApkReport
from .compare import Diff
from .permissions import describe as describe_permission
from .suspicious import RiskAssessment


_TIER_BADGE = {
    "high": "HIGH",
    "elevated": "ELEVATED",
    "normal": "normal",
    "unknown": "unknown",
}

# Ordering: highest-risk first so reviewers see dangerous perms at the top.
_TIER_ORDER = {"high": 0, "elevated": 1, "unknown": 2, "normal": 3}


def _bullets(items: list[str], limit: int = 50) -> str:
    if not items:
        return "_none_"
    shown = items[:limit]
    out = "\n".join(f"- `{x}`" for x in shown)
    if len(items) > limit:
        out += f"\n- _...and {len(items) - limit} more_"
    return out


def _permissions_table(perms: list[str]) -> str:
    """Render permissions as a Markdown table with description + risk tier."""
    if not perms:
        return "_none_"

    rows = []
    for p in perms:
        desc, tier = describe_permission(p)
        rows.append((p, tier, desc))
    # Sort by risk tier (high first), then by name
    rows.sort(key=lambda r: (_TIER_ORDER.get(r[1], 99), r[0]))

    out = ["| Permission | Risk | What it does |", "|---|---|---|"]
    for name, tier, desc in rows:
        # Escape pipes inside descriptions so Markdown tables don't break
        safe_desc = desc.replace("|", "\\|")
        out.append(f"| `{name}` | {_TIER_BADGE.get(tier, tier)} | {safe_desc} |")
    return "\n".join(out)


def render_markdown(
    report: ApkReport,
    risk: RiskAssessment,
    diff: Optional[Diff] = None,
) -> str:
    lines: list[str] = []
    lines.append(f"# APK Analysis Report")
    lines.append("")
    lines.append(f"_Generated: {datetime.utcnow().isoformat()}Z_")
    lines.append("")

    lines.append("## Summary")
    lines.append("")
    lines.append(f"- **File:** `{Path(report.file_path).name}`")
    lines.append(f"- **Size:** {report.file_size:,} bytes")
    lines.append(f"- **Package:** `{report.package}`")
    lines.append(f"- **Label:** {report.app_label}")
    lines.append(f"- **Version:** {report.version_name} (code {report.version_code})")
    lines.append(f"- **SDK:** min {report.min_sdk}, target {report.target_sdk}")
    lines.append(f"- **SHA-256:** `{report.sha256}`")
    lines.append(f"- **MD5:** `{report.md5}`")
    lines.append("")

    lines.append("## Risk Assessment")
    lines.append("")
    lines.append(
        f"**Level: {risk.level}** ({risk.score}/{risk.max_score})"
    )
    lines.append("")
    if risk.indicators:
        for ind in risk.indicators:
            lines.append(f"- {ind}")
    else:
        lines.append("_No phishing indicators detected._")
    lines.append("")

    lines.append("## Signing Certificates")
    lines.append("")
    if not report.certificates:
        lines.append("_No certificates found._")
    for i, c in enumerate(report.certificates, 1):
        lines.append(f"**Cert {i}**")
        lines.append(f"- Subject: `{c.subject}`")
        lines.append(f"- Issuer: `{c.issuer}`")
        lines.append(f"- Self-signed: {c.self_signed}")
        lines.append(f"- SHA-1: `{c.sha1}`")
        lines.append(f"- SHA-256: `{c.sha256}`")
        lines.append(f"- Valid: {c.not_before} -> {c.not_after}")
        lines.append("")

    lines.append("## Permissions")
    lines.append("")
    lines.append(_permissions_table(report.permissions))
    lines.append("")

    if report.declared_permissions:
        lines.append("### Custom Declared Permissions")
        lines.append("")
        lines.append(_bullets(report.declared_permissions))
        lines.append("")

    lines.append("## Components")
    lines.append("")
    lines.append(f"- Main activity: `{report.main_activity}`")
    lines.append(f"- Activities: {len(report.activities)}")
    lines.append(f"- Services: {len(report.services)}")
    lines.append(f"- Receivers: {len(report.receivers)}")
    lines.append(f"- Providers: {len(report.providers)}")
    lines.append("")

    if report.intent_schemes or report.intent_hosts:
        lines.append("### Deep Links / Intent Filters")
        lines.append("")
        lines.append("**Schemes:** " + (", ".join(f"`{s}`" for s in report.intent_schemes) or "_none_"))
        lines.append("")
        lines.append("**Hosts:** " + (", ".join(f"`{h}`" for h in report.intent_hosts) or "_none_"))
        lines.append("")

    lines.append("## Native Libraries")
    lines.append("")
    lines.append(_bullets(report.native_libs))
    lines.append("")

    lines.append("## Suspicious API Indicators")
    lines.append("")
    if not report.suspicious_api_hits:
        lines.append("_None detected._")
    else:
        for cat, hits in report.suspicious_api_hits.items():
            lines.append(f"- **{cat}**")
            for h in hits:
                lines.append(f"  - `{h}`")
    lines.append("")

    lines.append("## URLs & Domains")
    lines.append("")
    lines.append(f"### URLs ({len(report.urls)})")
    lines.append("")
    lines.append(_bullets(report.urls, limit=75))
    lines.append("")
    lines.append(f"### Domains ({len(report.domains)})")
    lines.append("")
    lines.append(_bullets(report.domains, limit=75))
    lines.append("")

    lines.append("## DEX Files")
    lines.append("")
    lines.append(f"- Count: {report.dex_count}")
    for h in report.dex_sha256:
        lines.append(f"- `{h}`")
    lines.append("")

    if diff is not None:
        lines.append("---")
        lines.append("")
        lines.append("# Comparison vs Reference APK")
        lines.append("")
        lines.append(f"- Suspect: **{diff.suspect_name}**")
        lines.append(f"- Reference: **{diff.reference_name}**")
        lines.append(f"- Package match: **{diff.package_match}**")
        lines.append(f"- Label match: **{diff.label_match}**")
        lines.append(f"- Signing cert match: **{diff.cert_match}**")
        if not diff.cert_match:
            lines.append("")
            lines.append("> **CERTIFICATE MISMATCH** — this is the single strongest")
            lines.append("> indicator that the suspect APK is NOT from the same publisher")
            lines.append("> as the reference. Legitimate updates from the same publisher")
            lines.append("> preserve the signing key.")
            lines.append("")
            lines.append(f"- Suspect cert SHA-256: {diff.suspect_cert_sha256}")
            lines.append(f"- Reference cert SHA-256: {diff.reference_cert_sha256}")
        lines.append("")

        if diff.version_change:
            lines.append(f"- Version change: {diff.version_change}")
            lines.append("")

        lines.append("## Permissions added by suspect")
        lines.append("")
        lines.append(_bullets(diff.permissions_added))
        lines.append("")
        lines.append("## Permissions removed in suspect")
        lines.append("")
        lines.append(_bullets(diff.permissions_removed))
        lines.append("")

        lines.append("## Activities added")
        lines.append("")
        lines.append(_bullets(diff.activities_added))
        lines.append("")
        lines.append("## Services added")
        lines.append("")
        lines.append(_bullets(diff.services_added))
        lines.append("")
        lines.append("## Receivers added")
        lines.append("")
        lines.append(_bullets(diff.receivers_added))
        lines.append("")
        lines.append("## URLs added")
        lines.append("")
        lines.append(_bullets(diff.urls_added, limit=75))
        lines.append("")
        lines.append("## Domains added")
        lines.append("")
        lines.append(_bullets(diff.domains_added, limit=75))
        lines.append("")

    return "\n".join(lines)


def _permissions_detailed(perms: list[str]) -> list[dict]:
    out = []
    for p in perms:
        desc, tier = describe_permission(p)
        out.append({"name": p, "risk_tier": tier, "description": desc})
    out.sort(key=lambda r: (_TIER_ORDER.get(r["risk_tier"], 99), r["name"]))
    return out


def render_json(
    report: ApkReport,
    risk: RiskAssessment,
    diff: Optional[Diff] = None,
) -> str:
    report_dict = report.to_dict()
    report_dict["permissions_detailed"] = _permissions_detailed(report.permissions)
    payload = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "report": report_dict,
        "risk": {
            "level": risk.level,
            "score": risk.score,
            "max_score": risk.max_score,
            "indicators": risk.indicators,
        },
        "diff": diff.to_dict() if diff else None,
    }
    return json.dumps(payload, indent=2, default=str)
