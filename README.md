# APK Phishing Analysis Bot

A Python tool your team can use to triage suspected phishing APKs. Drop an APK in, get a Markdown + JSON report out, and optionally diff the suspect against a known-legitimate reference APK.

## What it extracts

- File hashes (MD5 / SHA-1 / SHA-256) and size
- Package name, app label, version, min/target SDK
- Signing certificate chain (subject, issuer, fingerprints, validity, self-signed flag)
- All permissions (normal + custom declared) with high-risk flagging
- Activities / services / receivers / providers (counts and main activity)
- Deep link schemes and hosts from intent filters
- Native libraries (`lib/*.so`)
- Hardcoded URLs and domains extracted from DEX strings
- Suspicious API indicators (SMS interception, accessibility abuse, overlay, device admin, dynamic code loading, reflection, root detection, install-packages)
- Per-DEX SHA-256
- A risk score (`CLEAN` / `LOW` / `MEDIUM` / `HIGH`) with human-readable indicators

## Compare mode

Pass `--reference legit.apk` and the report adds a diff section. The most valuable signal here is the **signing certificate SHA-256** — legitimate updates from the same publisher always preserve the signing key. A certificate mismatch on an app that claims to be the same package is one of the strongest phishing indicators you can get.

The diff also shows added/removed permissions, activities, services, receivers, URLs, and domains.

## Setup

```
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

## Usage

Single APK:

```
python cli.py analyze suspicious.apk
```

Compare against a reference:

```
python cli.py analyze suspicious.apk --reference legit.apk --out ./reports
```

Outputs `reports/<sha256prefix>.md` and `reports/<sha256prefix>.json`.

## Project layout

```
cli.py                 # command-line entry point
apk_phish_bot/
  analyzer.py          # APK extraction (androguard)
  suspicious.py        # phishing-oriented risk scoring
  compare.py           # suspect-vs-reference diff
  report.py            # Markdown + JSON rendering
requirements.txt
```

Each module is small and focused so you can wrap `analyze_apk()` / `assess()` / `diff_reports()` / `render_markdown()` in whatever front-end you like later — a Slack bot, Discord bot, or Flask upload page can all call the same functions.

## Scope and limits

- **APK only for now.** IPA support is a separate (larger) lift — App Store binaries are FairPlay-encrypted and need decryption on a jailbroken device first. Open a follow-up when you want to tackle it.
- **Triage, not verdict.** High risk score means "a human should look at this," not "this is definitely malware." Treat the tool as a fast forensic extractor.
- **Only analyze apps you have permission to analyze** — your own apps, samples from your team's phishing reports, or targets under an authorized engagement.
