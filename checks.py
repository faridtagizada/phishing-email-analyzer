"""
checks.py - all the phishing checks are in this file.

Every check returns a list of "findings". A finding is just a dict:
    {"points": 3, "area": "links", "text": "what I found"}
At the end the points of all findings are added up to get the score.
"""

import hashlib
import ipaddress
import re
import socket
from email.utils import parseaddr
from html.parser import HTMLParser
from urllib.parse import urlsplit


# ------------------------------------------------------------------ lists

FREE_MAIL = {
    "gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "live.com",
    "mail.ru", "inbox.ru", "list.ru", "bk.ru", "yandex.ru", "yandex.com",
    "icloud.com", "proton.me", "protonmail.com", "gmx.com", "aol.com",
}

# words that make a sender name sound "official"
OFFICIAL_WORDS = [
    "bank", "support", "security", "service", "admin", "helpdesk", "billing",
    "dəstək", "xidmət", "təhlükəsizlik", "inzibatçı", "hesab",
]

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "cutt.ly", "rebrand.ly", "shorturl.at", "rb.gy", "t.ly", "tiny.cc", "s.id",
}

# cheap TLDs that show up a lot in phishing reports
# (.zip and .mov are extra sneaky because they look like file names)
CHEAP_TLDS = {
    "zip", "mov", "top", "xyz", "click", "icu", "tk", "ml", "ga", "cf",
    "gq", "rest", "cam", "country",
}

# endings where the real domain has 3 parts, e.g. aztu.edu.az
TWO_PART_SUFFIXES = {
    "com.az", "net.az", "org.az", "gov.az", "edu.az", "info.az", "biz.az",
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.tr", "gov.tr", "edu.tr", "com.ru",
    "co.jp", "ne.jp", "or.jp", "com.au", "net.au", "org.au", "co.nz", "co.za",
    "co.in", "co.kr", "co.il", "com.br", "com.cn", "com.mx", "com.ua", "com.sg", "com.hk",
}

DANGEROUS_EXT = {
    ".exe", ".scr", ".com", ".pif", ".bat", ".cmd", ".js", ".jse", ".vbs",
    ".vbe", ".wsf", ".hta", ".ps1", ".lnk", ".msi", ".jar", ".cpl", ".reg",
    ".dll", ".sys", ".ocx",
}
MACRO_EXT = {".docm", ".xlsm", ".pptm", ".dotm", ".xlam"}
WEBPAGE_EXT = {".html", ".htm", ".shtml", ".svg"}
ARCHIVE_EXT = {".zip", ".rar", ".7z", ".iso", ".img", ".gz", ".cab"}
DOCUMENT_EXT = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".txt", ".jpg", ".jpeg", ".png"}
# for these an "MZ" header is normal
PROGRAM_EXT = {".exe", ".dll", ".scr", ".com", ".sys", ".cpl", ".ocx"}

# tricks people use to fake a domain: n0vabank -> novabank, rnicrosoft -> microsoft
SWAPS = [("rn", "m"), ("vv", "w"), ("0", "o"), ("1", "l"), ("3", "e"), ("5", "s")]

FAIL_REASONS = {
    "spf": "the server that sent it is not allowed to send mail for this domain",
    "dkim": "the signature doesn't match, the mail may be forged or changed",
    "dmarc": "the From domain isn't backed by SPF/DKIM, typical for spoofing",
}

# the first alternative keeps the closing "]" of an IPv6 host: http://[2001:db8::1]/login
URL_RE = re.compile(r"https?://(?:\[[0-9a-f:.%]+\][^\s<>\"')\]]*|[^\s<>\"')\]]+)", re.IGNORECASE)

# addresses that only exist inside a network: never the place a mail really came from
INTERNAL_NETS = [ipaddress.ip_network(net) for net in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16", "100.64.0.0/10",
    "::1/128", "fc00::/7", "fe80::/10",
)]


# ---------------------------------------------------------------- helpers

def finding(points, area, text):
    return {"points": points, "area": area, "text": text}


def load_list(path):
    # one item per line, lines starting with # are comments
    items = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                items.append(line)
    return items


def normalize(text):
    # Python lowercases "İ" to "i" + a combining dot (2 characters!) and "I"
    # to "i" (not "ı"), so without this "HESABINIZ" would never match
    # "hesabınız" from the keyword list. Easiest fix: turn every i-like letter
    # into a plain "i". The keywords go through the same function, so both
    # sides still match.
    text = text.replace("İ", "i").replace("I", "i").lower()
    text = text.replace("ı", "i").replace("̇", "")
    # "verify your\naccount" must still match the keyword "verify your account"
    return " ".join(text.split())


def get_domain(address):
    # 'NovaBank <support@novabank.example>' -> 'novabank.example'
    _, email_address = parseaddr(address or "")
    if "@" not in email_address:
        return ""
    return email_address.rsplit("@", 1)[1].lower().strip()


def base_domain(host):
    # mail.novabank.example -> novabank.example
    # Real tools use the Public Suffix List for this. Mine is a guess that
    # works for normal .com / .az / .ru domains.
    parts = (host or "").lower().strip(".").split(".")
    if len(parts) >= 3 and ".".join(parts[-2:]) in TWO_PART_SUFFIXES:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def is_ip(host):
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass
    # Browsers also open an IPv4 address written as one number, in hex or in octal:
    # http://3405803785/ and http://0xcb.0.0x71.5/ are both 203.0.113.5
    host = host or ""
    if re.fullmatch(r"[0-9a-fx.]+", host, re.IGNORECASE) and re.search(r"\d", host):
        try:
            socket.inet_aton(host)
            return True
        except OSError:
            return False
    return False


def is_internal_ip(text):
    try:
        ip = ipaddress.ip_address(text)
    except ValueError:
        return False
    return any(ip in net for net in INTERNAL_NETS if net.version == ip.version)


def defang_ip(ip):
    return ip.replace(".", "[.]").replace(":", "[:]")


def safe_split(url):
    # urlsplit() raises ValueError for things like "http://[::1" (broken IPv6 brackets).
    # One broken link must not stop the whole analysis, so callers get None instead.
    try:
        return urlsplit(url)
    except ValueError:
        return None


def levenshtein(a, b):
    # how many single letter changes (insert, delete, replace) turn a into b
    previous = list(range(len(b) + 1))
    for i, char_a in enumerate(a, 1):
        current = [i]
        for j, char_b in enumerate(b, 1):
            cost = 0 if char_a == char_b else 1
            current.append(min(previous[j] + 1,          # delete
                               current[j - 1] + 1,       # insert
                               previous[j - 1] + cost))  # replace
        previous = current
    return previous[-1]


def unswap(label):
    for fake, real in SWAPS:
        label = label.replace(fake, real)
    return label


def defang(url):
    # hxxp://evil[.]example/... can be pasted into a chat or a ticket
    # without turning into a clickable link
    url = "".join(ch for ch in url if ch not in "\t\r\n")   # urlsplit() drops these as well
    parts = safe_split(url)
    if parts is not None and not parts.netloc:
        return url
    if parts is None or parts.netloc not in url:
        return re.sub(r"(?i)http", "hxxp", url).replace(".", "[.]")
    scheme = parts.scheme.replace("http", "hxxp")
    rest = url.split(parts.netloc, 1)[1]
    # a second address in the path or query (?u=http://other.example) must not stay clickable either
    rest = re.sub(r"(?i)http(s?)://", r"hxxp\1://", rest)
    return f"{scheme}://{parts.netloc.replace('.', '[.]')}{rest}"


def decode_punycode(host):
    try:
        return host.encode("ascii").decode("idna")
    except UnicodeError:
        return host


# ---------------------------------------------------------------- domains

def contains_brand(name, brand):
    # "paypal-login" and "securepaypal" both use the brand. A short brand has to stand on its own,
    # otherwise "pineapple" would count as an Apple look-alike.
    if brand not in name:
        return False
    if len(brand) >= 6:
        return True
    return re.search(rf"(^|[^a-z]){re.escape(brand)}([^a-z]|$)", name) is not None


def check_lookalike(host, trusted):
    # Is this domain pretending to be one of the real ones in trusted_domains.txt?
    if not host or is_ip(host):
        return None
    host = host.lower().strip(".")
    domain = base_domain(host)
    if domain in trusted:
        return None
    name = domain.split(".")[0]
    # paypal.com.secure-login.example: the trusted name is only a subdomain, the owner is the last part
    subdomains = host[:-len(domain)].strip(".")
    if subdomains:
        for real in sorted(trusted):
            if subdomains == real or subdomains.startswith(real + ".") or subdomains.endswith("." + real):
                return finding(3, "domains", f"{host} starts with {real}, but it really belongs to {domain}")
    for real in sorted(trusted):
        real_name = real.split(".")[0]
        if name == real_name:
            continue  # same name with another ending (.com / .az), can't tell
        if unswap(name) == unswap(real_name):
            return finding(3, "domains", f"{domain} imitates {real} (look-alike characters)")
        # two typos are a lot for a short name (moodle is 2 letters away from google), so those get 1
        distance = levenshtein(name, real_name)
        if len(real_name) >= 5 and distance <= (2 if len(real_name) >= 8 else 1):
            return finding(3, "domains", f"{domain} is only {distance} letter(s) away from {real}")
        # unswap here too, so micros0ft-login.com is caught as well
        if len(real_name) >= 4 and contains_brand(unswap(name), unswap(real_name)):
            return finding(2, "domains", f"{domain} uses the name '{real_name}' but it is not {real}")
    return None


# ---------------------------------------------------------------- headers

def check_auth(msg, authserv_id=None):
    # The receiving mail server writes its SPF / DKIM / DMARC verdict into
    # Authentication-Results. Careful: a sender can add a fake one too, so only
    # the TOP one (added by your own mail server) should be trusted. If your server
    # doesn't add one, the top one IS the sender's: pass authserv_id (the name your
    # server puts at the start of the header) and every other header is ignored.
    results = {"spf": "missing", "dkim": "missing", "dmarc": "missing"}
    headers = [str(h) for h in (msg.get_all("Authentication-Results") or [])]
    ignored = 0
    if authserv_id:
        wanted = authserv_id.strip().lower()
        own = [h for h in headers if h.split(";", 1)[0].strip().lower().split()[:1] == [wanted]]
        ignored = len(headers) - len(own)
        headers = own
    if headers:
        top = headers[0]
        for name in results:
            match = re.search(rf"\b{name}=(\w+)", top, re.IGNORECASE)
            if match:
                results[name] = match.group(1).lower()
    if results["spf"] == "missing" and msg.get("Received-SPF") and not authserv_id:
        results["spf"] = str(msg["Received-SPF"]).split()[0].lower()

    findings = []
    for name, result in results.items():
        label = name.upper()
        if result in ("fail", "permerror"):
            findings.append(finding(2, "auth", f"{label} = {result}: {FAIL_REASONS[name]}"))
        elif result in ("softfail", "neutral", "none"):
            findings.append(finding(1, "auth", f"{label} = {result}: doesn't prove who the sender is"))
    if ignored:
        findings.append(finding(0, "auth", f"Ignored {ignored} Authentication-Results header(s) not written by {authserv_id}"))
    if not headers and (authserv_id or not msg.get("Received-SPF")):
        findings.append(finding(0, "auth", "No Authentication-Results header, can't tell if SPF/DKIM/DMARC passed"))
    return results, findings


def check_sender(msg, trusted):
    findings = []
    from_header = str(msg.get("From", ""))
    name, address = parseaddr(from_header)
    from_domain = get_domain(from_header)
    name_norm = normalize(name)

    if not from_domain:
        findings.append(finding(1, "sender", "No usable From address (the header is missing or broken)"))

    # "support@kapitalbank.az" <random@evil.example>: the name is a fake address
    if "@" in name and name.strip().lower() != address.lower():
        findings.append(finding(3, "sender", f"Display name pretends to be '{name.strip()}', the real address is {address}"))

    # official sounding name, but sent from a free mailbox (gmail, mail.ru ...)
    if base_domain(from_domain) in FREE_MAIL and any(normalize(w) in name_norm for w in OFFICIAL_WORDS):
        findings.append(finding(2, "sender", f"'{name}' sounds official but writes from a free mailbox ({from_domain})"))

    # the name mentions a brand from my trusted list, but the domain is something else
    squeezed = name_norm.replace(" ", "").replace("-", "")
    sender_base = base_domain(from_domain)
    for real in sorted(trusted):
        brand = normalize(real.split(".")[0]).replace("-", "")
        if len(brand) < 4 or brand not in squeezed:
            continue
        # one of the trusted domains, or the same name under another ending (amazon.co.uk), is not a mismatch
        if sender_base in trusted or sender_base.split(".")[0] == real.split(".")[0]:
            continue
        findings.append(finding(2, "sender", f"The name says '{name}' but the mail doesn't come from {real}"))
        break

    # replies would go somewhere else than the sender
    reply_domain = get_domain(str(msg.get("Reply-To", "") or ""))
    if reply_domain and from_domain and base_domain(reply_domain) != base_domain(from_domain):
        findings.append(finding(2, "sender", f"Reply-To goes to {reply_domain}, not to {from_domain}"))

    # bounce address on another domain. Newsletters do this too, so only 1 point
    bounce_domain = get_domain(str(msg.get("Return-Path", "") or ""))
    if bounce_domain and from_domain and base_domain(bounce_domain) != base_domain(from_domain):
        findings.append(finding(1, "sender", f"Return-Path is on {bounce_domain}, not on {from_domain}"))

    # the Message-ID is usually made by the sender's own mail server
    match = re.search(r"@([\w.-]+)", str(msg.get("Message-ID", "")))
    if match and from_domain and base_domain(match.group(1)) != base_domain(from_domain):
        findings.append(finding(1, "sender", f"Message-ID was made by {match.group(1)}, not by {from_domain}"))

    return findings


def parse_received(msg):
    # Every mail server adds its Received header ON TOP of the others, so the
    # list is upside down: the LAST header shows where the mail started.
    hops = []
    for header in reversed(msg.get_all("Received") or []):
        text = " ".join(str(header).split())
        sender = re.search(r"\bfrom\s+(\S+)", text)
        receiver = re.search(r"\bby\s+(\S+)", text)
        ip = ""
        for candidate in re.findall(r"\[(?:IPv6:)?([0-9A-Fa-f:.]+)\]", text):
            try:
                ip = str(ipaddress.ip_address(candidate))     # IPv4 or IPv6
                break
            except ValueError:
                continue
        hops.append({
            "from": sender.group(1) if sender else "?",
            "by": receiver.group(1) if receiver else "?",
            "ip": ip,
        })
    return hops


# ------------------------------------------------------------ body + links

class LinkCollector(HTMLParser):
    # Goes through the HTML and remembers every <a href="..."> together with
    # the text the reader actually sees. Also keeps the visible text for the
    # keyword check.
    def __init__(self):
        super().__init__()
        self.links = []
        self.text = []
        self.href = None
        self.link_text = []
        self.skip = False  # inside <style> or <script>

    def handle_starttag(self, tag, attrs):
        if tag in ("style", "script"):
            self.skip = True
        elif tag == "a":
            self.close_link(closed=False)   # an <a> that was never closed still counts
            self.href = dict(attrs).get("href")
            self.link_text = []
        elif tag in ("area", "form"):
            # image maps and forms send the reader somewhere too
            target = dict(attrs).get("href" if tag == "area" else "action")
            if target:
                self.links.append((target.strip(), ""))

    def handle_endtag(self, tag):
        if tag in ("style", "script"):
            self.skip = False
        elif tag == "a":
            self.close_link(closed=True)

    def close_link(self, closed):
        if self.href is None:
            return
        # Without a </a> nobody knows where the link text ends, so only the first piece is used.
        # Otherwise an unclosed <a> would swallow the rest of the mail as its "text".
        pieces = self.link_text if closed else self.link_text[:1]
        self.links.append((self.href.strip(), "".join(pieces).strip()))
        self.href = None

    def close(self):
        super().close()
        self.close_link(closed=False)       # the mail ended while an <a> was still open

    def handle_data(self, data):
        if self.skip:
            return
        self.text.append(data)
        if self.href is not None:
            self.link_text.append(data)


def get_bodies(msg):
    # returns (plain text, html) of the mail, attachments are skipped
    plain, html = [], []
    for part in msg.walk():
        if part.is_multipart() or part.get_content_disposition() == "attachment":
            continue
        content_type = part.get_content_type()
        if content_type not in ("text/plain", "text/html"):
            continue
        try:
            content = part.get_content()
        except (LookupError, UnicodeDecodeError):
            content = (part.get_payload(decode=True) or b"").decode("utf-8", errors="replace")
        if content_type == "text/plain":
            plain.append(content)
        else:
            html.append(content)
    return "\n".join(plain), "\n".join(html)


def extract_links(plain, html):
    # returns (list of {"url", "text"}, visible text of the html part)
    links = []
    collector = LinkCollector()
    if html:
        collector.feed(html)
        collector.close()
    for href, text in collector.links:
        href = "".join(ch for ch in href if ch not in "\t\r\n")
        if href.startswith("//"):
            href = "https:" + href      # protocol-relative link, the browser fills in the scheme
        if href.lower().startswith(("http://", "https://")):
            links.append({"url": href, "text": text})
    html_text = " ".join(collector.text)
    shown = [text for _, text in collector.links if text]
    for source in (plain, html_text):
        for url in URL_RE.findall(source):
            url = url.rstrip(".,;:!?")
            # an address that is only the visible text of a link is not a link of its own
            if source is html_text and any(url in text for text in shown):
                continue
            if not any(link["url"] == url for link in links):
                links.append({"url": url, "text": ""})
    return links, html_text


def host_in_text(text):
    # if the visible link text looks like an address, return its domain:
    # "https://novabank.example/hesabim" -> "novabank.example", "Click here" -> None
    text = text.strip().lower()
    match = re.match(r"^(?:https?://)?((?:[a-z0-9-]+\.)+[a-z]{2,})(?:[/:?#]|$)", text)
    if not match:
        # "Visit https://bank.example now": the address is somewhere inside the text
        match = re.search(r"(?:https?://|www\.)((?:[a-z0-9-]+\.)+[a-z]{2,})", text)
    return match.group(1) if match else None


def check_links(links, trusted):
    findings = []
    seen_hosts = set()
    plain_http = False
    for link in links:
        url = link["url"]
        parts = safe_split(url)
        if parts is None:
            findings.append(finding(2, "links", f"Broken link that can't be parsed (sometimes done on purpose): {defang(url)}"))
            continue
        host = (parts.hostname or "").lower()
        if not host:
            continue

        # the text shows one site, but the link really goes to another one
        shown = host_in_text(link["text"])
        if shown and base_domain(shown) != base_domain(host):
            findings.append(finding(3, "links", f"Link text shows {shown} but it really goes to {host}"))

        if parts.scheme.lower() == "http":
            plain_http = True

        # http://kapitalbank.az@evil.example -> the browser ignores everything before @
        if "@" in parts.netloc:
            findings.append(finding(2, "links", f"Link uses the '@' trick: {defang(url)}"))

        if host in seen_hosts:
            continue
        seen_hosts.add(host)

        if is_ip(host):
            findings.append(finding(2, "links", f"Link goes straight to an IP address ({host}), real companies use domain names"))
            continue
        if base_domain(host) in SHORTENERS:
            findings.append(finding(1, "links", f"Shortened link ({host}) hides where it really goes"))
        if "xn--" in host:
            findings.append(finding(2, "links", f"Punycode domain {host} is really '{decode_punycode(host)}' (look-alike letters?)"))
        if host.rsplit(".", 1)[-1] in CHEAP_TLDS:
            findings.append(finding(1, "links", f"{host} uses a cheap TLD that scammers like"))
        if host.count(".") >= 4:
            findings.append(finding(1, "links", f"Very long domain with many parts: {host}"))
        lookalike = check_lookalike(host, trusted)
        if lookalike:
            findings.append(lookalike)

    if plain_http:
        findings.append(finding(1, "links", "Some links use plain http (no encryption)"))
    return findings


# ------------------------------------------------------------ attachments

def get_attachments(msg):
    files = []
    for part in msg.walk():
        if part.is_multipart():
            continue
        name = part.get_filename()
        if part.get_content_disposition() != "attachment" and not name:
            continue
        data = part.get_payload(decode=True) or b""
        files.append({
            "name": name or "(no name)",
            "type": part.get_content_type(),
            "size": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
            "data": data,
        })
    return files


def check_attachments(files):
    findings = []
    for f in files:
        # Windows drops trailing dots and spaces, so "invoice.exe." is saved as invoice.exe
        pieces = f["name"].lower().strip().rstrip(". ").split(".")
        ext = "." + pieces[-1] if len(pieces) > 1 else ""
        ext_before = "." + pieces[-2] if len(pieces) > 2 else ""

        if ext in DANGEROUS_EXT:
            findings.append(finding(3, "attachments", f"{f['name']}: {ext} files can run code when opened"))
            if ext_before in DOCUMENT_EXT:
                findings.append(finding(2, "attachments", f"{f['name']}: double extension, Windows hides '{ext}' so it looks like a {ext_before} file"))
        elif ext in MACRO_EXT:
            findings.append(finding(2, "attachments", f"{f['name']}: Office file with macros"))
        elif ext in WEBPAGE_EXT:
            findings.append(finding(2, "attachments", f"{f['name']}: HTML/SVG opens in the browser, often a fake login page"))
        elif ext in ARCHIVE_EXT:
            findings.append(finding(1, "attachments", f"{f['name']}: archive / disk image, often used to sneak files past filters"))

        # don't trust the name, look at the first bytes of the file too
        if f["data"][:2] == b"MZ" and ext not in PROGRAM_EXT:
            findings.append(finding(3, "attachments", f"{f['name']}: starts with 'MZ', so it's really a Windows program"))
    return findings


# ---------------------------------------------------------------- content

def check_keywords(subject, text, keywords):
    haystack = normalize(subject + " " + text)
    hits = [word for word in keywords if normalize(word) in haystack]
    if not hits:
        return []
    # 1 point per word, max 3, otherwise long mails get punished too much
    return [finding(min(len(hits), 3), "content", "Pressure / bait words: " + ", ".join(hits[:8]))]


def check_fake_reply(msg):
    # "RE: your order" but it isn't really a reply to anything
    subject = str(msg.get("Subject", ""))
    if re.match(r"^\s*(re|fw|fwd)\s*:", subject, re.IGNORECASE):
        if not msg.get("In-Reply-To") and not msg.get("References"):
            return [finding(1, "content", "Subject starts with RE:/FW: but it isn't really a reply")]
    return []
