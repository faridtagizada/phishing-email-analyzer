"""
Tests for the checks. Run from the project folder:

    python -m unittest discover tests -v
"""

import contextlib
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


class TestVirusTotal(unittest.TestCase):
    # no real network here, urlopen is replaced with a fake answer
    def setUp(self):
        virustotal._last_lookup = None      # no pause between the tests
        virustotal._cache.clear()           # every test asks again

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


class TestAuditFixes(unittest.TestCase):
    # one test per problem found in the audit; each of them fails on the old code

    def test_broken_url_is_reported_not_fatal(self):
        links, _ = checks.extract_links("see http://[2001:db8::1]/login and http://[oops/x", "")
        self.assertEqual([link["url"] for link in links], ["http://[2001:db8::1]/login", "http://[oops/x"])
        texts = " | ".join(f["text"] for f in checks.check_links(links, TRUSTED))
        self.assertIn("IP address (2001:db8::1)", texts)
        self.assertIn("Broken link", texts)
        self.assertEqual(checks.defang("http://exa\tmple.example/a"), "hxxp://example[.]example/a")

    def test_unclosed_link_and_bare_address_in_html(self):
        html = ('<p><a href="http://203.0.113.9/login">https://kapitalbank.az</p>'
                '<p>or open http://evil.example/x</p>')
        links, _ = checks.extract_links("", html)
        urls = [link["url"] for link in links]
        self.assertIn("http://203.0.113.9/login", urls)
        self.assertIn("http://evil.example/x", urls)
        self.assertNotIn("https://kapitalbank.az", urls)    # only the visible text of the first link
        texts = " | ".join(f["text"] for f in checks.check_links(links, TRUSTED))
        self.assertIn("Link text shows kapitalbank.az but it really goes to 203.0.113.9", texts)

    def test_protocol_relative_link(self):
        links, _ = checks.extract_links("", '<a href="//evil.example/login">log in</a>')
        self.assertEqual(links[0]["url"], "https://evil.example/login")

    def test_short_names_need_a_closer_match(self):
        trusted = TRUSTED | {"google.com", "apple.com"}
        self.assertIsNone(checks.check_lookalike("moodle.org", trusted))
        self.assertIsNone(checks.check_lookalike("pineapple.com", trusted))
        self.assertIsNotNone(checks.check_lookalike("gooogle.com", trusted))
        self.assertIsNotNone(checks.check_lookalike("apple-id-check.com", trusted))

    def test_real_mail_domains_of_the_brands(self):
        trusted = {domain.lower() for domain in checks.load_list(phish_analyzer.TRUSTED_FILE)}
        msg = make_mail({"From": "Facebook <notification@facebookmail.com>"})
        self.assertEqual(checks.check_sender(msg, trusted), [])
        self.assertIsNone(checks.check_lookalike("facebookmail.com", trusted))
        msg = make_mail({"From": "Amazon.co.uk <order-update@amazon.co.uk>"})
        self.assertEqual(checks.check_sender(msg, trusted), [])

    def test_evasions(self):
        self.assertEqual(checks.check_lookalike("paypal.com.secure-login.example", TRUSTED)["points"], 3)
        self.assertTrue(checks.is_ip("3405803785"))
        self.assertTrue(checks.is_ip("0xcb.0.0x71.5"))
        self.assertFalse(checks.is_ip("cafe.de"))
        self.assertEqual(checks.host_in_text("Visit https://kapitalbank.az today"), "kapitalbank.az")
        self.assertIsNone(checks.host_in_text("Download invoice.pdf"))

    def test_authserv_id(self):
        msg = make_mail({"Authentication-Results": "attacker.example; spf=pass; dkim=pass; dmarc=pass",
                         "From": "a@b.example"})
        results, _ = checks.check_auth(msg)
        self.assertEqual(results["spf"], "pass")            # the top header is believed by default
        results, findings = checks.check_auth(msg, "mx.mycompany.example")
        self.assertEqual(results, {"spf": "missing", "dkim": "missing", "dmarc": "missing"})
        self.assertIn("Ignored 1", findings[0]["text"])

    def test_keyword_split_over_two_lines(self):
        found = checks.check_keywords("", "Please verify your\naccount today", ["verify your account"])
        self.assertEqual(found[0]["points"], 1)

    def test_dll_and_trailing_dot(self):
        found = checks.check_attachments([{"name": "update.dll", "data": b"MZ\x90"}])
        self.assertEqual(found[0]["points"], 3)
        found = checks.check_attachments([{"name": "invoice.js.", "data": b"x"}])
        self.assertEqual(found[0]["points"], 3)

    def test_missing_from(self):
        msg = make_mail({"Reply-To": "x@evil.example", "Subject": "hi"})
        texts = [f["text"] for f in checks.check_sender(msg, TRUSTED)]
        self.assertEqual(texts, ["No usable From address (the header is missing or broken)"])

    def test_received_ipv6_and_internal_hops(self):
        msg = make_mail({"Received": "from a.example ([IPv6:2001:db8::25]) by mx.example with ESMTP",
                         "From": "a@b.example"})
        self.assertEqual(checks.parse_received(msg)[0]["ip"], "2001:db8::25")
        self.assertTrue(checks.is_internal_ip("192.168.1.5"))
        self.assertFalse(checks.is_internal_ip("203.0.113.45"))

    def test_defang_second_url(self):
        self.assertEqual(checks.defang("https://a.example/r?u=http://b.example/x"),
                         "hxxps://a[.]example/r?u=hxxp://b.example/x")

    def test_control_characters_are_not_printed(self):
        self.assertEqual(phish_analyzer.clean("Invoice\x1b[2K\x1b[1A Score: 0"), "Invoice\\x1b[2K\\x1b[1A Score: 0")
        self.assertEqual(phish_analyzer.clean("Təcili: hesabınız"), "Təcili: hesabınız")

    def test_batch_survives_a_bad_file_and_json_is_a_list(self):
        good = os.path.join(ROOT, "samples", "legit_newsletter.eml")
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "r.json")
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                rc = phish_analyzer.main([os.path.join(tmp, "missing.eml"), good, "--json", out, "--no-color"])
            self.assertEqual(rc, 1)             # one file failed ...
            with open(out, encoding="utf-8") as f:
                data = json.load(f)
            self.assertEqual(len(data), 1)      # ... the other one was still analyzed, and JSON is a list
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(phish_analyzer.main([good, "--no-color"]), 0)

    def test_existing_file_name_is_not_a_pattern(self):
        with tempfile.TemporaryDirectory() as tmp:
            for name in ("msg[1].eml", "msg1.eml"):
                open(os.path.join(tmp, name), "w").close()
            literal = os.path.join(tmp, "msg[1].eml")
            self.assertEqual(phish_analyzer.expand_paths([literal]), [literal])
            self.assertEqual(len(phish_analyzer.expand_paths([os.path.join(tmp, "*.eml")])), 2)

    def test_virustotal_pause_is_kept_between_mails(self):
        answer = {"data": {"attributes": {"last_analysis_stats": {"malicious": 0, "undetected": 60}}}}
        clock = mock.Mock()
        clock.monotonic.side_effect = [100.0, 100.0, 103.0, 115.0]
        virustotal._last_lookup = None
        virustotal._cache.clear()
        with mock.patch("urllib.request.urlopen", side_effect=lambda *a, **k: io.BytesIO(json.dumps(answer).encode())), \
                mock.patch.object(virustotal, "time", clock):
            virustotal.lookup_hash("ab" * 32, "key")
            virustotal.lookup_hash("cd" * 32, "key")
        clock.sleep.assert_called_once_with(12.0)


def parse_mail(raw):
    return BytesParser(policy=policy.default).parsebytes(raw.encode("utf-8"))


def run_main(argv):
    out = io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
        rc = phish_analyzer.main(argv)
    return rc, out.getvalue()


class TestSecondRound(unittest.TestCase):
    # the audit findings the first round of fixes had not covered yet

    def test_homograph_domains(self):
        links = [{"url": "https://раураl.com/login", "text": ""}]       # Cyrillic р, а, у
        texts = " | ".join(f["text"] for f in checks.check_links(links, TRUSTED))
        self.assertIn("not Latin (really xn--", texts)
        self.assertIn("imitates paypal.com with look-alike letters", texts)
        found = checks.check_lookalike("xn--80aa0cbo65f.com", TRUSTED)  # the same trick, written as punycode
        self.assertEqual(found["points"], 3)
        self.assertIsNone(checks.check_lookalike("bücher.example", TRUSTED))   # a normal IDN that copies nothing

    def test_same_name_with_another_ending(self):
        self.assertEqual(checks.check_lookalike("paypal.co", TRUSTED)["points"], 2)
        self.assertIn("same name as kapitalbank.az", checks.check_lookalike("kapitalbank.com", TRUSTED)["text"])
        self.assertIsNone(checks.check_lookalike("online.kapitalbank.az", TRUSTED))
        trusted = {domain.lower() for domain in checks.load_list(phish_analyzer.TRUSTED_FILE)}
        self.assertIsNone(checks.check_lookalike("amazon.co.uk", trusted))      # listed as a real second domain

    def test_file_name_is_not_a_domain(self):
        self.assertIsNone(checks.host_in_text("Q3-report.pdf"))
        self.assertIsNone(checks.host_in_text("invoice.zip"))
        self.assertEqual(checks.host_in_text("https://invoice.zip"), "invoice.zip")
        links = [{"url": "https://files.example/q3.pdf", "text": "Q3-report.pdf"}]
        self.assertEqual(checks.check_links(links, TRUSTED), [])

    def test_link_text_is_always_defanged(self):
        self.assertEqual(checks.defang_text("novabank.example/login"), "novabank[.]example/login")
        self.assertEqual(checks.defang_text("Visit https://bank.example"), "Visit hxxps://bank[.]example")
        self.assertEqual(checks.defang_text("Click here"), "Click here")
        mail = ('From: a@b.example\nSubject: hi\nContent-Type: text/html\n\n'
                '<a href="http://evil.example/x">novabank.example/login</a>')
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "m.eml")
            with open(path, "w", encoding="utf-8") as f:
                f.write(mail)
            _, out = run_main([path, "--no-color"])
        self.assertIn("text on screen: novabank[.]example/login", out)
        self.assertNotIn("novabank.example/login", out)

    def test_ioc_ip_is_the_one_the_receiving_side_saw(self):
        msg = parse_mail(
            "Received: from mx.mycompany.example (mx.mycompany.example [192.0.2.10]) by inbox.mycompany.example\n"
            "Received: from mail.evil.example (mail.evil.example [203.0.113.7]) by mx.mycompany.example\n"
            "Received: from trusted.bank.example (trusted.bank.example [198.51.100.99]) by mail.evil.example\n"
            "From: a@b.example\n\nhi")
        self.assertEqual(checks.sending_server_ip(checks.parse_received(msg)), "203.0.113.7")   # not the forged line
        msg = parse_mail(   # Microsoft 365: "(address)" without brackets, internal hops with public IPv6 addresses
            "Received: from AM6PR04MB1.eurprd04.prod.outlook.com (2603:10a6:20b:1::1) by"
            " AM9PR04MB2.eurprd04.prod.outlook.com (2603:10a6:20b:2::2) with HTTPS\n"
            "Received: from mail.evil.example (203.0.113.8) by DB5EUR03FT012.mail.protection.outlook.com"
            " (10.152.20.80) with Microsoft SMTP Server\n"
            "From: a@b.example\n\nhi")
        hops = checks.parse_received(msg)
        self.assertEqual(hops[0]["ip"], "203.0.113.8")          # the sender's address, not the receiver's
        self.assertEqual(checks.sending_server_ip(hops), "203.0.113.8")

    def test_more_dangerous_file_types(self):
        def points(name, data=b"x"):
            return [f["points"] for f in checks.check_attachments([{"name": name, "data": data}])]
        self.assertEqual(points("addin.xll", b"MZ\x90"), [3])     # a DLL by design: not counted twice
        for name in ("help.chm", "link.url", "setup.msix", "setup.appx"):
            self.assertEqual(points(name), [3], name)
        self.assertEqual(points("notes.one"), [2])
        self.assertEqual(points("data.xlsb"), [2])
        self.assertEqual(points("disk.vhdx"), [1])

    def test_fail_on_exit_code_and_json_folder(self):
        bad = os.path.join(ROOT, "samples", "phishing_bank.eml")
        good = os.path.join(ROOT, "samples", "legit_newsletter.eml")
        self.assertEqual(run_main([bad, "--no-color", "--fail-on", "high"])[0], 3)
        self.assertEqual(run_main([good, "--no-color", "--fail-on", "medium"])[0], 0)
        self.assertEqual(run_main([bad, "--no-color"])[0], 0)          # without --fail-on the verdict doesn't count
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as bad_argument:
            phish_analyzer.main([good, "--fail-on", "low"])
        self.assertEqual(bad_argument.exception.code, 2)
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "reports", "today.json")
            self.assertEqual(run_main([good, "--no-color", "--json", out])[0], 0)
            self.assertTrue(os.path.exists(out))

    def test_trusted_site_is_not_an_ioc(self):
        report = {"from": "", "reply_to": "", "route": [], "attachments": [],
                  "links": [{"url": "https://www.paypal.com/help", "text": ""},
                            {"url": "http://evil.example/login", "text": ""}]}
        iocs = phish_analyzer.collect_iocs(report, TRUSTED)
        self.assertEqual(iocs["domain"], ["evil[.]example"])     # blocking paypal.com would block the real PayPal

    def test_virustotal_looks_up_a_file_once(self):
        answer = {"data": {"attributes": {"last_analysis_stats": {"malicious": 1, "undetected": 60}}}}
        virustotal._cache.clear()
        virustotal._last_lookup = None
        with mock.patch("urllib.request.urlopen",
                        side_effect=lambda *a, **k: io.BytesIO(json.dumps(answer).encode())) as urlopen:
            first = virustotal.lookup_hash("ef" * 32, "key")
            second = virustotal.lookup_hash("ef" * 32, "key")
        self.assertEqual(first, second)
        self.assertEqual(urlopen.call_count, 1)
        virustotal._cache.clear()

    @unittest.skipIf(os.name == "nt", "Windows has no executable bit")
    def test_script_can_be_started_directly(self):
        self.assertTrue(os.access(os.path.join(ROOT, "phish_analyzer.py"), os.X_OK))


if __name__ == "__main__":
    unittest.main()
