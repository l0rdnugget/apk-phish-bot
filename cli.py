"""Command-line entry point.

Usage:
    python cli.py analyze suspicious.apk
    python cli.py analyze suspicious.apk --reference legit.apk
    python cli.py analyze suspicious.apk --reference legit.apk --out ./reports

Produces <outdir>/<sha256>.md and <outdir>/<sha256>.json.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from apk_phish_bot.analyzer import analyze_apk
from apk_phish_bot.compare import diff_reports
from apk_phish_bot.report import render_json, render_markdown
from apk_phish_bot.suspicious import assess


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="apk-phish-bot",
        description="Analyze an APK for phishing indicators and optionally diff it against a reference.",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_an = sub.add_parser("analyze", help="Analyze a single APK")
    p_an.add_argument("apk", help="Path to suspect APK")
    p_an.add_argument(
        "--reference",
        "-r",
        help="Optional path to a known-legitimate reference APK for side-by-side diff",
    )
    p_an.add_argument(
        "--out",
        "-o",
        default="./reports",
        help="Directory to write reports into (default: ./reports)",
    )

    args = parser.parse_args(argv)

    if args.cmd != "analyze":
        parser.print_help()
        return 2

    suspect_path = Path(args.apk)
    if not suspect_path.is_file():
        print(f"error: APK not found: {suspect_path}", file=sys.stderr)
        return 1

    print(f"[*] Analyzing {suspect_path.name} ...")
    suspect = analyze_apk(suspect_path)

    diff = None
    if args.reference:
        ref_path = Path(args.reference)
        if not ref_path.is_file():
            print(f"error: reference APK not found: {ref_path}", file=sys.stderr)
            return 1
        print(f"[*] Analyzing reference {ref_path.name} ...")
        reference = analyze_apk(ref_path)
        diff = diff_reports(suspect, reference)

    risk = assess(suspect)

    md = render_markdown(suspect, risk, diff)
    js = render_json(suspect, risk, diff)

    outdir = Path(args.out)
    outdir.mkdir(parents=True, exist_ok=True)
    stem = suspect.sha256[:16] or suspect_path.stem
    md_path = outdir / f"{stem}.md"
    js_path = outdir / f"{stem}.json"
    md_path.write_text(md, encoding="utf-8")
    js_path.write_text(js, encoding="utf-8")

    print(f"[+] Risk: {risk.level} ({risk.score}/{risk.max_score})")
    print(f"[+] Wrote {md_path}")
    print(f"[+] Wrote {js_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
