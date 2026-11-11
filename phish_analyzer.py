#!/usr/bin/env python3
"""
phish_analyzer.py - looks at a suspicious email (.eml file) and tells you
how "phishy" it is.

    python phish_analyzer.py samples/phishing_bank.eml
    python phish_analyzer.py samples/*.eml
    python phish_analyzer.py mail.eml --json report.json
    python phish_analyzer.py mail.eml --vt       (needs VT_API_KEY, see README)
    python phish_analyzer.py mail.eml --authserv-id mx.example.com

Exit code: 0 = every file was analyzed, 1 = at least one file could not be read or analyzed.

Only uses the Python standard library.
"""

import argparse
import glob
import json
import os
import sys
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr

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


def clean(text):
    # Everything printed from the mail (subject, names, link texts, file names) is written by
    # the sender. Escape codes and other control characters could wipe the screen or paint a
    # fake "Score: 0 -> LOW" line, so they are shown as \x1b, \n ... instead of being sent
    # to the terminal.
    return "".join(ch if ch.isprintable() else ch.encode("unicode_escape").decode("ascii") for ch in str(text))


def analyze(path, keywords, trusted, vt_key=None, authserv_id=None):
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
    report["auth"], auth_findings = checks.check_auth(msg, authserv_id)
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
        for f in files:
            # lookup_hash keeps the pause the free API needs, also between two mails
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
    # The first server with a public address is where the mail came from (10.x / 192.168.x
    # hops are somebody's internal network). Keep in mind that the sender can add fake
    # Received lines below the real ones, so treat this address as a lead, not as proof.
    for hop in report["route"]:
        if hop["ip"] and not checks.is_internal_ip(hop["ip"]):
            add("ip", checks.defang_ip(hop["ip"]))
            break
    for link in report["links"]:
        parts = checks.safe_split(link["url"])
        host = ((parts.hostname if parts else "") or "").lower()
        if checks.is_ip(host):
            add("ip", checks.defang_ip(host))
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
    print(c(" " + clean(os.path.basename(report["file"])), "bold"))
    print(line)
    print(f" Subject : {clean(report['subject'])}")
    print(f" From    : {clean(report['from'])}")
    if report["reply_to"]:
        print(f" Reply-To: {clean(report['reply_to'])}")
    print(f" Date    : {clean(report['date'])}")

    print(c("\n[ SPF / DKIM / DMARC ]", "cyan"))
    for name, result in report["auth"].items():
        color = "green" if result == "pass" else "red" if result in ("fail", "permerror") else "yellow"
        print(f"  {name.upper():<6} {c(clean(result), color)}")

    if report["route"]:
        print(c("\n[ Route ] first server at the top", "cyan"))
        for i, hop in enumerate(report["route"], 1):
            ip = f" [{hop['ip']}]" if hop["ip"] else ""
            print(f"  {i}. {clean(hop['from'])}{ip} -> {clean(hop['by'])}")

    print(c("\n[ Links ] defanged", "cyan"))
    if not report["links"]:
        print("  none")
    for link in report["links"]:
        print(f"  {clean(checks.defang(link['url']))}")
        text = link["text"]
        if text and text != link["url"]:
            shown = checks.defang(text) if text.lower().startswith("http") else text
            print(f"     text on screen: {clean(shown)}")

    print(c("\n[ Attachments ]", "cyan"))
    if not report["attachments"]:
        print("  none")
    for f in report["attachments"]:
        print(f"  {clean(f['name'])}  ({clean(f['type'])}, {f['size']} bytes)")
        print(f"     sha256: {f['sha256']}")
        if "virustotal" in f:
            print(f"     VirusTotal: {clean(virustotal.describe(f['virustotal']))}")

    print(c("\n[ Findings ]", "cyan"))
    if not report["findings"]:
        print("  nothing suspicious found")
    for item in sorted(report["findings"], key=lambda x: -x["points"]):
        points = f"+{item['points']}"
        if item["points"] >= 3:
            points = c(points, "red")
        elif item["points"] >= 1:
            points = c(points, "yellow")
        print(f"  {points}  {item['area']:<12} {clean(item['text'])}")

    # IOCs only make sense if the mail is suspicious
    if report["verdict"] != "LOW":
        print(c("\n[ IOCs ] safe to copy into a ticket", "cyan"))
        for kind, values in report["iocs"].items():
            for value in values:
                print(f"  {kind:<7} {clean(value)}")

    color = {"HIGH": "red", "MEDIUM": "yellow", "LOW": "green"}[report["verdict"]]
    filled = min(report["score"], 20)
    bar = "#" * filled + "." * (20 - filled)
    print("\n" + "-" * 70)
    print(f" Score: {report['score']}  ->  {c(report['verdict'], color)}  [{c(bar, color)}]")
    print(f" {report['advice']}")
    print(line + "\n")


def expand_paths(patterns):
    # Windows cmd doesn't expand *.eml by itself, so do it here. A name that exists is taken
    # as it is: "msg[1].eml" is a file name, not a pattern that happens to match msg1.eml.
    paths = []
    for pattern in patterns:
        if os.path.exists(pattern):
            paths.append(pattern)
        else:
            paths += sorted(glob.glob(pattern)) or [pattern]
    return paths


def main(argv=None):
    parser = argparse.ArgumentParser(description="Check .eml files for signs of phishing.")
    parser.add_argument("files", nargs="+", help=".eml file(s) to check")
    parser.add_argument("--json", metavar="FILE", help="also save the results as JSON (always a list, one item per file)")
    parser.add_argument("--vt", action="store_true", help="look up attachment hashes on VirusTotal (needs VT_API_KEY)")
    parser.add_argument("--authserv-id", metavar="NAME",
                        help="only trust Authentication-Results headers written by this server (e.g. mx.example.com)")
    parser.add_argument("--no-color", action="store_true", help="plain output without colors")
    args = parser.parse_args(argv)

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
            print("[!] --vt needs an API key in VT_API_KEY (see README). Skipping VirusTotal.\n", file=sys.stderr)

    reports = []
    failed = 0
    for path in expand_paths(args.files):
        try:
            report = analyze(path, keywords, trusted, vt_key, args.authserv_id)
        except OSError as e:
            print(f"[!] Can't read {path}: {e}", file=sys.stderr)
            failed += 1
            continue
        except Exception as e:  # one mail this tool can't handle must not stop the other files
            print(f"[!] Could not analyze {path}: {type(e).__name__}: {e}", file=sys.stderr)
            failed += 1
            continue
        print_report(report, use_color)
        reports.append(report)

    if len(reports) > 1:
        print("Summary")
        for report in reports:
            print(f"  {report['verdict']:<7} {report['score']:>3}  {clean(os.path.basename(report['file']))}")
        print()

    if args.json and reports:
        try:
            with open(args.json, "w", encoding="utf-8") as f:
                json.dump(reports, f, ensure_ascii=False, indent=2)
        except OSError as e:
            print(f"[!] Can't write {args.json}: {e}", file=sys.stderr)
            return 1
        print(f"[+] Saved JSON to {args.json}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
