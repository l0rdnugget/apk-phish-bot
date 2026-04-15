"""Core APK extraction logic.

Uses androguard to pull metadata, manifest info, signing certificates,
permissions, components, URLs, and file hashes out of an APK.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any

from androguard.core.bytecodes.apk import APK
from androguard.core.bytecodes.dvm import DalvikVMFormat


# Matches http(s) URLs and bare domain-ish strings. Kept deliberately loose;
# noise is filtered downstream.
URL_RE = re.compile(rb"https?://[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]+")
DOMAIN_RE = re.compile(
    rb"(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+"
    rb"(?:com|net|org|io|co|app|dev|xyz|info|ru|cn|br|de|uk|us|me|tk|top|site|online|click|link)"
)


@dataclass
class CertInfo:
    subject: str = ""
    issuer: str = ""
    serial: str = ""
    sha1: str = ""
    sha256: str = ""
    not_before: str = ""
    not_after: str = ""
    self_signed: bool = False


@dataclass
class ApkReport:
    """Everything we extract from a single APK."""

    file_path: str = ""
    file_size: int = 0
    md5: str = ""
    sha1: str = ""
    sha256: str = ""

    package: str = ""
    app_label: str = ""
    version_name: str = ""
    version_code: str = ""
    min_sdk: str = ""
    target_sdk: str = ""
    max_sdk: str = ""

    main_activity: str = ""
    activities: list[str] = field(default_factory=list)
    services: list[str] = field(default_factory=list)
    receivers: list[str] = field(default_factory=list)
    providers: list[str] = field(default_factory=list)

    permissions: list[str] = field(default_factory=list)
    declared_permissions: list[str] = field(default_factory=list)

    intent_schemes: list[str] = field(default_factory=list)
    intent_hosts: list[str] = field(default_factory=list)

    native_libs: list[str] = field(default_factory=list)
    features: list[str] = field(default_factory=list)

    certificates: list[CertInfo] = field(default_factory=list)

    urls: list[str] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)

    dex_count: int = 0
    dex_sha256: list[str] = field(default_factory=list)

    suspicious_api_hits: dict[str, list[str]] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _file_hashes(path: Path) -> tuple[int, str, str, str]:
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    size = 0
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            size += len(chunk)
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
    return size, md5.hexdigest(), sha1.hexdigest(), sha256.hexdigest()


def _cert_info(apk: APK) -> list[CertInfo]:
    certs: list[CertInfo] = []
    # androguard returns x509 Certificate objects from asn1crypto
    raw_certs = []
    try:
        raw_certs.extend(apk.get_certificates())
    except Exception:
        pass
    for cert in raw_certs:
        try:
            subject = cert.subject.human_friendly
            issuer = cert.issuer.human_friendly
            info = CertInfo(
                subject=str(subject),
                issuer=str(issuer),
                serial=str(cert.serial_number),
                sha1=cert.sha1_fingerprint.replace(" ", "").lower(),
                sha256=cert.sha256_fingerprint.replace(" ", "").lower(),
                not_before=str(cert["tbs_certificate"]["validity"]["not_before"].native),
                not_after=str(cert["tbs_certificate"]["validity"]["not_after"].native),
                self_signed=(subject == issuer),
            )
            certs.append(info)
        except Exception:
            continue
    return certs


def _intent_filters(apk: APK) -> tuple[list[str], list[str]]:
    schemes: set[str] = set()
    hosts: set[str] = set()
    try:
        manifest = apk.get_android_manifest_xml()
        ns = "{http://schemas.android.com/apk/res/android}"
        for data in manifest.iter("data"):
            scheme = data.get(f"{ns}scheme")
            host = data.get(f"{ns}host")
            if scheme:
                schemes.add(scheme)
            if host:
                hosts.add(host)
    except Exception:
        pass
    return sorted(schemes), sorted(hosts)


# API calls commonly seen in banking / credential phishing Android malware.
SUSPICIOUS_APIS: dict[str, list[str]] = {
    "SMS interception": [
        "Landroid/telephony/SmsManager;->sendTextMessage",
        "Landroid/provider/Telephony$Sms",
        "android.provider.Telephony.SMS_RECEIVED",
    ],
    "Accessibility abuse": [
        "Landroid/accessibilityservice/AccessibilityService;",
        "android.accessibilityservice.AccessibilityService",
    ],
    "Overlay / screen capture": [
        "Landroid/view/WindowManager$LayoutParams;->TYPE_APPLICATION_OVERLAY",
        "TYPE_SYSTEM_ALERT_WINDOW",
        "Landroid/media/projection/MediaProjection;",
    ],
    "Device admin": [
        "Landroid/app/admin/DevicePolicyManager;",
        "android.app.admin.DeviceAdminReceiver",
    ],
    "Dynamic code loading": [
        "Ldalvik/system/DexClassLoader;",
        "Ldalvik/system/PathClassLoader;",
        "Ljava/lang/Runtime;->exec",
    ],
    "Reflection (possible obfuscation)": [
        "Ljava/lang/reflect/Method;->invoke",
    ],
    "Install unknown sources": [
        "android.intent.action.INSTALL_PACKAGE",
        "REQUEST_INSTALL_PACKAGES",
    ],
    "Root detection / SU": [
        "/system/xbin/su",
        "/system/bin/su",
    ],
}


def _scan_suspicious_apis(dex_blobs: list[bytes]) -> dict[str, list[str]]:
    hits: dict[str, list[str]] = {}
    joined = b"\n".join(dex_blobs)
    for category, needles in SUSPICIOUS_APIS.items():
        found = []
        for needle in needles:
            if needle.encode("utf-8", errors="ignore") in joined:
                found.append(needle)
        if found:
            hits[category] = found
    return hits


def _extract_urls(dex_blobs: list[bytes]) -> tuple[list[str], list[str]]:
    urls: set[str] = set()
    domains: set[str] = set()
    for blob in dex_blobs:
        for m in URL_RE.findall(blob):
            try:
                urls.add(m.decode("utf-8", errors="ignore"))
            except Exception:
                continue
        for m in DOMAIN_RE.findall(blob):
            try:
                domains.add(m.decode("utf-8", errors="ignore").lower())
            except Exception:
                continue
    # Filter noise: android framework, schemas, etc.
    noise = (
        "schemas.android.com",
        "xmlpull.org",
        "w3.org",
        "apache.org",
        "java.sun.com",
        "ns.adobe.com",
        "googleapis.com/auth",
    )
    urls = {u for u in urls if not any(n in u for n in noise)}
    domains = {d for d in domains if not any(n in d for n in noise)}
    return sorted(urls), sorted(domains)


def analyze_apk(apk_path: str | Path) -> ApkReport:
    """Parse an APK and return a populated ApkReport."""
    path = Path(apk_path)
    if not path.is_file():
        raise FileNotFoundError(f"APK not found: {path}")

    size, md5, sha1, sha256 = _file_hashes(path)

    apk = APK(str(path))

    report = ApkReport(
        file_path=str(path),
        file_size=size,
        md5=md5,
        sha1=sha1,
        sha256=sha256,
        package=apk.get_package() or "",
        app_label=apk.get_app_name() or "",
        version_name=str(apk.get_androidversion_name() or ""),
        version_code=str(apk.get_androidversion_code() or ""),
        min_sdk=str(apk.get_min_sdk_version() or ""),
        target_sdk=str(apk.get_target_sdk_version() or ""),
        max_sdk=str(apk.get_max_sdk_version() or ""),
        main_activity=apk.get_main_activity() or "",
        activities=sorted(apk.get_activities() or []),
        services=sorted(apk.get_services() or []),
        receivers=sorted(apk.get_receivers() or []),
        providers=sorted(apk.get_providers() or []),
        permissions=sorted(apk.get_permissions() or []),
        declared_permissions=sorted(apk.get_declared_permissions() or []),
        native_libs=sorted(apk.get_libraries() or []),
        features=sorted(apk.get_features() or []),
        certificates=_cert_info(apk),
    )

    report.intent_schemes, report.intent_hosts = _intent_filters(apk)

    # Collect DEX blobs
    dex_blobs: list[bytes] = []
    dex_hashes: list[str] = []
    try:
        all_dex = apk.get_all_dex()
        for blob in all_dex:
            dex_blobs.append(blob)
            dex_hashes.append(hashlib.sha256(blob).hexdigest())
    except Exception:
        pass
    report.dex_count = len(dex_blobs)
    report.dex_sha256 = dex_hashes

    report.urls, report.domains = _extract_urls(dex_blobs)
    report.suspicious_api_hits = _scan_suspicious_apis(dex_blobs)

    return report
