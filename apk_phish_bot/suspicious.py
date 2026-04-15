"""Phishing-oriented heuristic scoring for an ApkReport.

This is intentionally opinionated and conservative. It flags indicators
commonly seen in credential / banking phishing APKs. A high score does NOT
prove malice; it means the sample deserves human review.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .analyzer import ApkReport


# Permissions that phishing / banking-trojan APKs disproportionately request.
HIGH_RISK_PERMISSIONS = {
    "android.permission.RECEIVE_SMS",
    "android.permission.READ_SMS",
    "android.permission.SEND_SMS",
    "android.permission.WRITE_SMS",
    "android.permission.BIND_ACCESSIBILITY_SERVICE",
    "android.permission.BIND_DEVICE_ADMIN",
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.REQUEST_INSTALL_PACKAGES",
    "android.permission.READ_CONTACTS",
    "android.permission.READ_PHONE_STATE",
    "android.permission.CALL_PHONE",
    "android.permission.PROCESS_OUTGOING_CALLS",
    "android.permission.RECORD_AUDIO",
    "android.permission.GET_ACCOUNTS",
    "android.permission.USE_CREDENTIALS",
    "android.permission.READ_CALL_LOG",
    "android.permission.WRITE_CALL_LOG",
    "android.permission.ACCESS_NOTIFICATION_POLICY",
    "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE",
}


@dataclass
class RiskAssessment:
    score: int = 0
    max_score: int = 0
    indicators: list[str] = field(default_factory=list)

    @property
    def level(self) -> str:
        if self.max_score == 0:
            return "UNKNOWN"
        ratio = self.score / self.max_score
        if ratio >= 0.66:
            return "HIGH"
        if ratio >= 0.33:
            return "MEDIUM"
        if ratio > 0:
            return "LOW"
        return "CLEAN"


def assess(report: ApkReport) -> RiskAssessment:
    ra = RiskAssessment()

    def add(points: int, cap: int, reason: str) -> None:
        ra.max_score += cap
        if points > 0:
            ra.score += min(points, cap)
            ra.indicators.append(reason)
        else:
            # Still counts against max so score stays meaningful
            pass

    # 1. High-risk permissions
    risky = sorted(set(report.permissions) & HIGH_RISK_PERMISSIONS)
    ra.max_score += 15
    if risky:
        pts = min(len(risky) * 3, 15)
        ra.score += pts
        ra.indicators.append(
            f"Requests {len(risky)} high-risk permission(s): {', '.join(risky)}"
        )

    # 2. Self-signed / suspicious certificate
    ra.max_score += 5
    if report.certificates:
        if any(c.self_signed for c in report.certificates):
            ra.score += 3
            ra.indicators.append("Self-signed certificate")
        # Android Debug cert is a classic giveaway
        for c in report.certificates:
            if "Android Debug" in c.subject or "CN=Android Debug" in c.subject:
                ra.score += 5
                ra.indicators.append("Signed with the Android Debug key")
                break
    else:
        ra.score += 2
        ra.indicators.append("No signing certificate found")

    # 3. Suspicious API usage
    ra.max_score += 15
    api_hits = report.suspicious_api_hits
    if api_hits:
        pts = min(len(api_hits) * 3, 15)
        ra.score += pts
        ra.indicators.append(
            "Suspicious API categories: " + ", ".join(sorted(api_hits.keys()))
        )

    # 4. Accessibility service declared
    ra.max_score += 5
    if "android.permission.BIND_ACCESSIBILITY_SERVICE" in report.permissions:
        ra.score += 5
        ra.indicators.append("Binds an AccessibilityService (common overlay-attack vector)")

    # 5. Device admin
    ra.max_score += 5
    if "android.permission.BIND_DEVICE_ADMIN" in report.permissions:
        ra.score += 5
        ra.indicators.append("Requests Device Admin (persistence / anti-uninstall)")

    # 6. Overlay
    ra.max_score += 5
    if "android.permission.SYSTEM_ALERT_WINDOW" in report.permissions:
        ra.score += 3
        ra.indicators.append("Can draw over other apps (overlay attacks)")

    # 7. Install other APKs
    ra.max_score += 5
    if "android.permission.REQUEST_INSTALL_PACKAGES" in report.permissions:
        ra.score += 3
        ra.indicators.append("Can install other APKs")

    # 8. Total permission count (bloat)
    ra.max_score += 5
    if len(report.permissions) > 30:
        ra.score += 3
        ra.indicators.append(f"High permission count ({len(report.permissions)})")

    return ra
