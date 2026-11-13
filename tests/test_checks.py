"""
Tests for the checks. Run from the project folder:

    python -m unittest discover tests -v
"""

import io
import json
import os
import sys
import tempfile
import unittest
import urllib.error
from email import policy
from email.parser import BytesParser
from unittest import mock

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, ROOT)

import checks          # noqa: E402
import phish_analyzer  # noqa: E402
import virustotal      # noqa: E402

TRUSTED = {"novabank.example", "kapitalbank.az", "paypal.com"}


def make_mail(headers, body="hello"):
    text = "".join(f"{name}: {value}\n" for name, value in headers.items()) + "\n" + body
    return BytesParser(policy=policy.default).parsebytes(text.encode("utf-8"))


class TestHelpers(unittest.TestCase):
    def test_azerbaijani_i_letters(self):
        # Python lowercases İ / I differently than Azerbaijani does
        self.assertEqual(checks.normalize("HESABINIZ BLOKLANIB"), checks.normalize("hesabınız bloklanıb"))
        self.assertEqual(checks.normalize("İSTİFADƏÇİ"), "istifadəçi")

    def test_defang(self):
        self.assertEqual(checks.defang("http://evil.example/a.php"), "hxxp://evil[.]example/a.php")
        self.assertEqual(checks.defang("https://1.2.3.4/x"), "hxxps://1[.]2[.]3[.]4/x")

    def test_base_domain(self):
        self.assertEqual(checks.base_domain("mail.kapitalbank.az"), "kapitalbank.az")
        self.assertEqual(checks.base_domain("student.aztu.edu.az"), "aztu.edu.az")

    def test_levenshtein(self):
        self.assertEqual(checks.levenshtein("novabank", "n0vabank"), 1)
        self.assertEqual(checks.levenshtein("paypal", "paypal"), 0)


class TestLookalike(unittest.TestCase):
    def test_swapped_characters(self):
        self.assertEqual(checks.check_lookalike("n0vabank.example", TRUSTED)["points"], 3)
        self.assertIsNotNone(checks.check_lookalike("paypa1.com", TRUSTED))

    def test_brand_inside_another_domain(self):
        self.assertEqual(checks.check_lookalike("kapitalbank-secure.az", TRUSTED)["points"], 2)
        self.assertEqual(checks.check_lookalike("paypa1-login.com", TRUSTED)["points"], 2)

    def test_real_domain_is_fine(self):
        self.assertIsNone(checks.check_lookalike("online.kapitalbank.az", TRUSTED))
        self.assertIsNone(checks.check_lookalike("ctfclub.example", TRUSTED))


class TestSender(unittest.TestCase):
    def test_official_name_from_free_mailbox(self):
        msg = make_mail({"From": "Kapital Bank Support <kapitalbank.help@gmail.com>"})
        texts = " | ".join(f["text"] for f in checks.check_sender(msg, TRUSTED))
        self.assertIn("free mailbox", texts)
        self.assertIn("doesn't come from kapitalbank.az", texts)

    def test_display_name_is_a_fake_address(self):
        msg = make_mail({"From": '"support@paypal.com" <x@evil.example>'})
        self.assertEqual(checks.check_sender(msg, TRUSTED)[0]["points"], 3)

    def test_fake_reply(self):
        msg = make_mail({"From": "a@b.example", "Subject": "RE: your order"})
        self.assertEqual(len(checks.check_fake_reply(msg)), 1)

    def test_missing_auth_header(self):
        results, findings = checks.check_auth(make_mail({"From": "a@b.example"}))
        self.assertEqual(results["spf"], "missing")
        self.assertEqual(findings[0]["points"], 0)


class TestLinks(unittest.TestCase):
    def test_text_and_real_link_differ(self):
        html = '<p><a href="http://evil.example/login">https://kapitalbank.az</a></p>'
        links, _ = checks.extract_links("", html)
        texts = [f["text"] for f in checks.check_links(links, TRUSTED)]
        self.assertTrue(any("really goes to evil.example" in t for t in texts))

    def test_click_here_is_not_a_mismatch(self):
        links, _ = checks.extract_links("", '<a href="https://kapitalbank.az/x">Click here</a>')
        self.assertEqual(checks.check_links(links, TRUSTED), [])

    def test_file_name_is_not_a_domain(self):
        # "Report.pdf" is what the reader sees, not a site the link pretends to be
        html = '<a href="https://files.kapitalbank.az/r/1">Report.pdf</a> <a href="https://kapitalbank.az/">index.html</a>'
        links, _ = checks.extract_links("", html)
        self.assertEqual(checks.check_links(links, TRUSTED), [])
        # a real address in the text is still compared
        links, _ = checks.extract_links("", '<a href="http://evil.example/">www.kapitalbank.az</a>')
        self.assertTrue(any("really goes to evil.example" in f["text"] for f in checks.check_links(links, TRUSTED)))

    def test_unclosed_and_nested_links_are_not_lost(self):
        # browsers still open these links, so an attacker must not be able to hide them
        html = ('<a href="http://evil.example/login">Log in<a href="https://kapitalbank.az/privacy">Privacy</a>'
                '<p><a href="http://203.0.113.9/x">no closing tag')
        links, _ = checks.extract_links("", html)
        urls = [link["url"] for link in links]
        self.assertEqual(urls, ["http://evil.example/login", "https://kapitalbank.az/privacy", "http://203.0.113.9/x"])
        self.assertEqual(links[0]["text"], "Log in")

    def test_broken_url_does_not_crash(self):
        links, _ = checks.extract_links("visit http://[203.0.113.5/login now", "")
        self.assertEqual(checks.check_links(links, TRUSTED), [])
        self.assertNotIn("203.0.113.5", checks.defang(links[0]["url"]))

    def test_ip_shortener_punycode_and_at_trick(self):
        links = [
            {"url": "http://203.0.113.5/login", "text": ""},
            {"url": "https://bit.ly/abc", "text": ""},
            {"url": "https://xn--pypal-4ve.example/", "text": ""},
            {"url": "https://kapitalbank.az@evil.example/", "text": ""},
        ]
        texts = " | ".join(f["text"] for f in checks.check_links(links, TRUSTED))
        self.assertIn("IP address", texts)
        self.assertIn("Shortened link", texts)
        self.assertIn("Punycode", texts)
        self.assertIn("'@' trick", texts)


class TestAttachments(unittest.TestCase):
    def test_double_extension(self):
        found = checks.check_attachments([{"name": "faktura.pdf.exe", "data": b"hi"}])
        self.assertEqual(sum(f["points"] for f in found), 5)

    def test_program_hiding_behind_pdf_name(self):
        found = checks.check_attachments([{"name": "invoice.pdf", "data": b"MZ\x90\x00"}])
        self.assertIn("MZ", found[0]["text"])

    def test_normal_pdf(self):
        self.assertEqual(checks.check_attachments([{"name": "cv.pdf", "data": b"%PDF-1.7"}]), [])


class TestSamples(unittest.TestCase):
    def test_verdicts(self):
        keywords = checks.load_list(phish_analyzer.KEYWORDS_FILE)
        trusted = set(checks.load_list(phish_analyzer.TRUSTED_FILE))
        expected = {
            "phishing_bank.eml": "HIGH",
            "suspicious_invoice.eml": "MEDIUM",
            "legit_newsletter.eml": "LOW",
        }
        for name, verdict in expected.items():
            report = phish_analyzer.analyze(os.path.join(ROOT, "samples", name), keywords, trusted)
            self.assertEqual(report["verdict"], verdict, name)


class TestIocs(unittest.TestCase):
    def test_trusted_link_domain_is_not_an_ioc(self):
        # scammers link to the real site too; it must not end up on a blocklist
        mail = (b"From: Bank <support@evil.example>\nSubject: test\nContent-Type: text/html\n\n"
                b'<a href="https://kapitalbank.az/privacy">Privacy</a> <a href="http://evil.example/login">Login</a>')
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "mail.eml")
            with open(path, "wb") as f:
                f.write(mail)
            report = phish_analyzer.analyze(path, [], TRUSTED)
        self.assertEqual(report["iocs"]["domain"], ["evil[.]example"])
        self.assertEqual(report["iocs"]["url"], ["hxxp://evil[.]example/login"])

    def test_broken_url_in_a_mail(self):
        mail = b"From: a@b.example\nSubject: test\n\nclick http://[203.0.113.5/login\n"
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "mail.eml")
            with open(path, "wb") as f:
                f.write(mail)
            report = phish_analyzer.analyze(path, [], TRUSTED)  # must not raise
        self.assertEqual(len(report["links"]), 1)


class TestVirusTotal(unittest.TestCase):
    # no real network here, urlopen is replaced with a fake answer
    def setUp(self):
        virustotal._last_lookup = None
        virustotal._cache.clear()

    @staticmethod
    def fake_answer(*args, **kwargs):
        answer = {"data": {"attributes": {"last_analysis_stats": {"malicious": 1, "undetected": 60}}}}
        return io.BytesIO(json.dumps(answer).encode())

    def test_waits_between_lookups(self):
        # second lookup 3 s after the first one -> wait the remaining 12 s
        with mock.patch("urllib.request.urlopen", side_effect=self.fake_answer), \
                mock.patch("virustotal.time.monotonic", side_effect=[100.0, 103.0, 115.0]), \
                mock.patch("virustotal.time.sleep") as sleep:
            virustotal.lookup_hash("aa" * 32, "key")
            virustotal.lookup_hash("bb" * 32, "key")
        sleep.assert_called_once_with(12.0)

    def test_same_file_is_looked_up_once(self):
        with mock.patch("urllib.request.urlopen", side_effect=self.fake_answer) as urlopen, \
                mock.patch("virustotal.time.sleep"):
            first = virustotal.lookup_hash("aa" * 32, "key")
            second = virustotal.lookup_hash("aa" * 32, "key")
        self.assertEqual(urlopen.call_count, 1)
        self.assertEqual(first, second)

    def test_wait_also_between_emails(self):
        # before, the 15 s pause only happened between attachments of the same email
        keywords = checks.load_list(phish_analyzer.KEYWORDS_FILE)
        trusted = set(checks.load_list(phish_analyzer.TRUSTED_FILE))
        with mock.patch("urllib.request.urlopen", side_effect=self.fake_answer), \
                mock.patch("virustotal.time.sleep") as sleep:
            for name in ("phishing_bank.eml", "suspicious_invoice.eml"):
                phish_analyzer.analyze(os.path.join(ROOT, "samples", name), keywords, trusted, vt_key="key")
        self.assertEqual(sleep.call_count, 1)

    def test_found(self):
        answer = {"data": {"attributes": {"last_analysis_stats": {"malicious": 3, "suspicious": 1, "undetected": 60}}}}
        fake = io.BytesIO(json.dumps(answer).encode())
        with mock.patch("urllib.request.urlopen", return_value=fake):
            result = virustotal.lookup_hash("ab" * 32, "key")
        self.assertEqual((result["malicious"], result["total"]), (3, 64))

    def test_not_found(self):
        error = urllib.error.HTTPError("url", 404, "Not Found", None, None)
        with mock.patch("urllib.request.urlopen", side_effect=error):
            self.assertEqual(virustotal.lookup_hash("ab" * 32, "key")["status"], "not found")


if __name__ == "__main__":
    unittest.main()
