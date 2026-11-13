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

# The free API allows 4 lookups per minute, so there must be 15 seconds
# between two lookups. The wait is kept here for the whole run, so it also
# works when several emails are checked one after another.
MIN_INTERVAL = 15
_last_lookup = None
# The same file attached to several emails is only looked up once
_cache = {}


def _wait_for_turn():
    global _last_lookup
    if _last_lookup is not None:
        wait = MIN_INTERVAL - (time.monotonic() - _last_lookup)
        if wait > 0:
            time.sleep(wait)
    _last_lookup = time.monotonic()


def lookup_hash(sha256, api_key, timeout=15):
    # returns e.g. {"status": "found", "malicious": 12, "suspicious": 1, "total": 70}
    if sha256 in _cache:
        return dict(_cache[sha256])
    _wait_for_turn()
    result = _query(sha256, api_key, timeout)
    if result["status"] != "error":  # errors (no internet, 429 ...) can be tried again
        _cache[sha256] = result
    return dict(result)


def _query(sha256, api_key, timeout):
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
