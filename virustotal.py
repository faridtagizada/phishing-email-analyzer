"""
virustotal.py - optional: look up attachment hashes on VirusTotal.

Only the SHA256 hash is sent, never the file itself. If you upload a file
to VirusTotal, people with a paid account can download it, which is not
great if it's someone's private document.

Get a free API key on virustotal.com and put it in the VT_API_KEY
environment variable. The free API allows 4 lookups per minute.
"""

import json
import time
import urllib.error
import urllib.request

API_URL = "https://www.virustotal.com/api/v3/files/"
MIN_INTERVAL = 15       # seconds between two lookups, the free API allows 4 per minute
_last_lookup = None     # when the previous lookup was made (shared by every mail of one run)


def wait_for_turn():
    # The limit is per API key, not per mail: when several mails are checked in one run
    # the pause has to be kept between them too.
    global _last_lookup
    now = time.monotonic()
    if _last_lookup is not None and now - _last_lookup < MIN_INTERVAL:
        time.sleep(MIN_INTERVAL - (now - _last_lookup))
    _last_lookup = time.monotonic()


def lookup_hash(sha256, api_key, timeout=15):
    # returns e.g. {"status": "found", "malicious": 12, "suspicious": 1, "total": 70}
    wait_for_turn()
    request = urllib.request.Request(API_URL + sha256, headers={"x-apikey": api_key})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            data = json.load(response)
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return {"status": "not found"}  # nobody uploaded this file yet
        if e.code == 401:
            return {"status": "error", "message": "API key was rejected"}
        if e.code == 429:
            return {"status": "error", "message": "too many requests (free API = 4 per minute)"}
        return {"status": "error", "message": f"HTTP {e.code}"}
    except OSError as e:  # no internet, DNS problem, timeout ...
        return {"status": "error", "message": f"network problem: {e}"}
    except ValueError:
        return {"status": "error", "message": "VirusTotal sent something that isn't JSON"}

    stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
    return {
        "status": "found",
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "total": sum(stats.values()),
    }


def describe(result):
    if result["status"] == "found":
        return f"{result['malicious']} malicious, {result['suspicious']} suspicious (out of {result['total']} engines)"
    if result["status"] == "not found":
        return "not known to VirusTotal"
    return "error: " + result.get("message", "?")
