#!/usr/bin/env python3
"""
phish_analyzer.py - looks at a suspicious email (.eml file) and tells you
how "phishy" it is.

    python phish_analyzer.py samples/phishing_bank.eml
    python phish_analyzer.py samples/*.eml
    python phish_analyzer.py mail.eml --json report.json
    python phish_analyzer.py mail.eml --vt       (needs VT_API_KEY, see README)

Only uses the Python standard library.
"""

import argparse
import glob
import json
import os
import sys
import time
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from urllib.parse import urlsplit

import checks
import virustotal

HERE = os.path.dirname(os.path.abspath(__file__))
KEYWORDS_FILE = os.path.join(HERE, "data", "keywords.txt")
TRUSTED_FILE = os.path.join(HERE, "data", "trusted_domains.txt")

COLORS = {
    "red": "\033[91m", "yellow": "\033[93m", "green": "\033[92m",
    "cyan": "\033[96m", "bold": "\033[1m", "end": "\033[0m",
}


def verdict(score):
    # my own numbers, I tuned them on the sample emails (see README)
    if score >= 7:
        return "HIGH", "Looks like phishing. Don't click anything, report it."
    if score >= 3:
        return "MEDIUM", "Suspicious. Check with the sender in another way before trusting it."
    return "LOW", "Nothing big found (that doesn't mean it's 100% safe)."


def analyze(path, keywords, trusted, vt_key=None):
    with open(path, "rb") as f:
        msg = BytesParser(policy=policy.default).parse(f)

    report = {
        "file": path,
        "subject": str(msg.get("Subject", "")),
        "from": str(msg.get("From", "")),
        "reply_to": str(msg.get("Reply-To", "") or ""),
        "date": str(msg.get("Date", "")),
    }
    findings = []

    # 1. headers
    report["auth"], auth_findings = checks.check_auth(msg)
    findings += auth_findings
    findings += checks.check_sender(msg, trusted)
    for header in ("From", "Reply-To", "Return-Path"):
        domain = checks.get_domain(str(msg.get(header, "") or ""))
        lookalike = checks.check_lookalike(domain, trusted)
        if lookalike:
            findings.append(lookalike)
    report["route"] = checks.parse_received(msg)

    # 2. links
    plain, html = checks.get_bodies(msg)
    report["links"], html_text = checks.extract_links(plain, html)
    findings += checks.check_links(report["links"], trusted)

    # 3. attachments
    files = checks.get_attachments(msg)
    findings += checks.check_attachments(files)
    if vt_key:
        for i, f in enumerate(files):
            if i > 0:
                time.sleep(15)  # free API: 4 requests per minute
            f["virustotal"] = virustotal.lookup_hash(f["sha256"], vt_key)
            vt = f["virustotal"]
            if vt["status"] == "found" and vt["malicious"] > 0:
                findings.append(checks.finding(5, "attachments", f"VirusTotal: {vt['malicious']} of {vt['total']} engines say {f['name']} is malicious"))
    for f in files:
        del f["data"]  # raw bytes don't belong in the report
    report["attachments"] = files

    # 4. text
    findings += checks.check_keywords(report["subject"], plain + " " + html_text, keywords)
    findings += checks.check_fake_reply(msg)

    # the same domain can show up in From and in a link, count it once
    unique = []
    for item in findings:
        if item not in unique:
            unique.append(item)

    report["findings"] = unique
    report["score"] = sum(item["points"] for item in unique)
    report["verdict"], report["advice"] = verdict(report["score"])
    report["iocs"] = collect_iocs(report)
    return report


def collect_iocs(report):
    # everything an analyst would copy into a ticket, defanged
    iocs = {"email": [], "ip": [], "domain": [], "url": [], "sha256": []}

    def add(kind, value):
        if value and value not in iocs[kind]:
            iocs[kind].append(value)

    for header in ("from", "reply_to"):
        _, address = parseaddr(report[header])
        if "@" in address:
            add("email", address.replace("@", "[@]").replace(".", "[.]"))
    if report["route"] and report["route"][0]["ip"]:
        add("ip", report["route"][0]["ip"].replace(".", "[.]"))  # first server = where it came from
    for link in report["links"]:
        host = (urlsplit(link["url"]).hostname or "").lower()
        if checks.is_ip(host):
            add("ip", host.replace(".", "[.]"))
        elif host:
            add("domain", host.replace(".", "[.]"))
        add("url", checks.defang(link["url"]))
    for f in report["attachments"]:
        add("sha256", f["sha256"])
    return iocs


def print_report(report, use_color):
    def c(text, color):
        return f"{COLORS[color]}{text}{COLORS['end']}" if use_color else text

    line = "=" * 70
    print(line)
    print(c(" " + os.path.basename(report["file"]), "bold"))
    print(line)
    print(f" Subject : {report['subject']}")
    print(f" From    : {report['from']}")
    if report["reply_to"]:
        print(f" Reply-To: {report['reply_to']}")
    print(f" Date    : {report['date']}")

    print(c("\n[ SPF / DKIM / DMARC ]", "cyan"))
    for name, result in report["auth"].items():
        color = "green" if result == "pass" else "red" if result in ("fail", "permerror") else "yellow"
        print(f"  {name.upper():<6} {c(result, color)}")

    if report["route"]:
        print(c("\n[ Route ] first server at the top", "cyan"))
        for i, hop in enumerate(report["route"], 1):
            ip = f" [{hop['ip']}]" if hop["ip"] else ""
            print(f"  {i}. {hop['from']}{ip} -> {hop['by']}")

    print(c("\n[ Links ] defanged", "cyan"))
    if not report["links"]:
        print("  none")
    for link in report["links"]:
        print(f"  {checks.defang(link['url'])}")
        text = link["text"]
        if text and text != link["url"]:
            shown = checks.defang(text) if text.lower().startswith("http") else text
            print(f"     text on screen: {shown}")

    print(c("\n[ Attachments ]", "cyan"))
    if not report["attachments"]:
        print("  none")
    for f in report["attachments"]:
        print(f"  {f['name']}  ({f['type']}, {f['size']} bytes)")
        print(f"     sha256: {f['sha256']}")
        if "virustotal" in f:
            print(f"     VirusTotal: {virustotal.describe(f['virustotal'])}")

    print(c("\n[ Findings ]", "cyan"))
    if not report["findings"]:
        print("  nothing suspicious found")
    for item in sorted(report["findings"], key=lambda x: -x["points"]):
        points = f"+{item['points']}"
        if item["points"] >= 3:
            points = c(points, "red")
        elif item["points"] >= 1:
            points = c(points, "yellow")
        print(f"  {points}  {item['area']:<12} {item['text']}")

    # IOCs only make sense if the mail is suspicious
    if report["verdict"] != "LOW":
        print(c("\n[ IOCs ] safe to copy into a ticket", "cyan"))
        for kind, values in report["iocs"].items():
            for value in values:
                print(f"  {kind:<7} {value}")

    color = {"HIGH": "red", "MEDIUM": "yellow", "LOW": "green"}[report["verdict"]]
    filled = min(report["score"], 20)
    bar = "#" * filled + "." * (20 - filled)
    print("\n" + "-" * 70)
    print(f" Score: {report['score']}  ->  {c(report['verdict'], color)}  [{c(bar, color)}]")
    print(f" {report['advice']}")
    print(line + "\n")


def main():
    parser = argparse.ArgumentParser(description="Check .eml files for signs of phishing.")
    parser.add_argument("files", nargs="+", help=".eml file(s) to check")
    parser.add_argument("--json", metavar="FILE", help="also save the results as JSON")
    parser.add_argument("--vt", action="store_true", help="look up attachment hashes on VirusTotal (needs VT_API_KEY)")
    parser.add_argument("--no-color", action="store_true", help="plain output without colors")
    args = parser.parse_args()

    # Windows consoles sometimes can't print letters like "ə", don't crash on that
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="replace")

    use_color = sys.stdout.isatty() and not args.no_color and "NO_COLOR" not in os.environ
    if use_color and os.name == "nt":
        os.system("")  # old trick that turns on color codes in Windows cmd

    keywords = checks.load_list(KEYWORDS_FILE)
    trusted = {domain.lower() for domain in checks.load_list(TRUSTED_FILE)}

    vt_key = None
    if args.vt:
        vt_key = os.environ.get("VT_API_KEY")
        if not vt_key:
            print("[!] --vt needs an API key in VT_API_KEY (see README). Skipping VirusTotal.\n")

    # Windows cmd doesn't expand *.eml by itself, so do it here
    paths = []
    for pattern in args.files:
        paths += sorted(glob.glob(pattern)) or [pattern]

    reports = []
    for path in paths:
        try:
            report = analyze(path, keywords, trusted, vt_key)
        except OSError as e:
            print(f"[!] Can't read {path}: {e}")
            continue
        print_report(report, use_color)
        reports.append(report)

    if len(reports) > 1:
        print("Summary")
        for report in reports:
            print(f"  {report['verdict']:<7} {report['score']:>3}  {os.path.basename(report['file'])}")
        print()

    if args.json and reports:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(reports if len(reports) > 1 else reports[0], f, ensure_ascii=False, indent=2)
        print(f"[+] Saved JSON to {args.json}")


if __name__ == "__main__":
    main()
