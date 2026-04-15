"""Diff two ApkReports (suspicious vs legitimate reference)."""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any

from .analyzer import ApkReport


@dataclass
class Diff:
    suspect_name: str = ""
    reference_name: str = ""

    package_match: bool = False
    label_match: bool = False

    cert_match: bool = False
    suspect_cert_sha256: list[str] = field(default_factory=list)
    reference_cert_sha256: list[str] = field(default_factory=list)

    permissions_added: list[str] = field(default_factory=list)
    permissions_removed: list[str] = field(default_factory=list)

    activities_added: list[str] = field(default_factory=list)
    activities_removed: list[str] = field(default_factory=list)

    services_added: list[str] = field(default_factory=list)
    services_removed: list[str] = field(default_factory=list)

    receivers_added: list[str] = field(default_factory=list)
    receivers_removed: list[str] = field(default_factory=list)

    urls_added: list[str] = field(default_factory=list)
    urls_removed: list[str] = field(default_factory=list)

    domains_added: list[str] = field(default_factory=list)
    domains_removed: list[str] = field(default_factory=list)

    version_change: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _set_diff(a: list[str], b: list[str]) -> tuple[list[str], list[str]]:
    """Return (added, removed) where added = a - b, removed = b - a."""
    sa, sb = set(a), set(b)
    return sorted(sa - sb), sorted(sb - sa)


def diff_reports(suspect: ApkReport, reference: ApkReport) -> Diff:
    d = Diff(
        suspect_name=suspect.app_label or suspect.package,
        reference_name=reference.app_label or reference.package,
        package_match=suspect.package == reference.package,
        label_match=suspect.app_label == reference.app_label,
    )

    d.suspect_cert_sha256 = [c.sha256 for c in suspect.certificates]
    d.reference_cert_sha256 = [c.sha256 for c in reference.certificates]
    d.cert_match = (
        bool(d.suspect_cert_sha256)
        and set(d.suspect_cert_sha256) == set(d.reference_cert_sha256)
    )

    d.permissions_added, d.permissions_removed = _set_diff(
        suspect.permissions, reference.permissions
    )
    d.activities_added, d.activities_removed = _set_diff(
        suspect.activities, reference.activities
    )
    d.services_added, d.services_removed = _set_diff(
        suspect.services, reference.services
    )
    d.receivers_added, d.receivers_removed = _set_diff(
        suspect.receivers, reference.receivers
    )
    d.urls_added, d.urls_removed = _set_diff(suspect.urls, reference.urls)
    d.domains_added, d.domains_removed = _set_diff(suspect.domains, reference.domains)

    if suspect.version_name != reference.version_name:
        d.version_change = f"{reference.version_name} -> {suspect.version_name}"

    return d
