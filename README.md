# phishing-email-analyzer

A small Python tool for checking suspicious emails. You give it an `.eml` file, it looks at the headers, the links and the attachments, and gives the email a score: **LOW**, **MEDIUM** or **HIGH**.

Nothing to install, it only uses the Python standard library.

## Why I made this

Phishing is still the easiest way into most companies, and I wanted to understand what actually gives a phishing email away. Reading about SPF, DKIM and DMARC is one thing, but writing code that checks them is what made it click for me.

Scam emails here in Azerbaijan are often written in Azerbaijani ("your card is blocked", "pay the delivery fee for your parcel"), so the tool knows Azerbaijani bait words too, not only English ones.

## What it checks

**Sender and authentication**
- SPF, DKIM and DMARC results from the `Authentication-Results` header
- `Reply-To` or `Return-Path` on a different domain than `From`
- display name tricks: a name that is itself an email address, an "official" name from a Gmail or mail.ru address, a brand name with someone else's domain
- `Message-ID` created by a different server
- the route the mail took (`Received` headers), first server first

**Links**
- link text that shows one site but really goes to another
- look-alike domains (`n0vabank` vs `novabank`, `rnicrosoft` vs `microsoft`, `paypa1` vs `paypal`), compared to a list of real domains in `data/trusted_domains.txt`
- links to raw IP addresses, URL shorteners, punycode domains, cheap TLDs, the `@` trick, plain http

**Attachments**
- files that can run code (`.exe`, `.js`, `.vbs`, `.lnk` ...) and double extensions like `.pdf.exe`
- HTML/SVG attachments, archives and Office files with macros
- the first bytes of the file: if it starts with `MZ` it's a Windows program, whatever the name says
- SHA256 of every attachment, plus an optional VirusTotal lookup

**Text**
- pressure and bait words in Azerbaijani and English (`data/keywords.txt`)
- fake `RE:` subjects that aren't really replies

At the end it lists the IOCs, defanged (`hxxp://evil[.]example`), so you can paste them into a chat or a ticket without creating clickable links. It can also save everything as JSON.

## How to run it

```bash
git clone https://github.com/faridtagizada/phishing-email-analyzer.git
cd phishing-email-analyzer
python phish_analyzer.py samples/phishing_bank.eml
```

Needs Python 3.8 or newer (use `python3` on Linux).

```bash
python phish_analyzer.py samples/*.eml                # several files + a summary
python phish_analyzer.py mail.eml --json report.json  # save the result as JSON (always a list, one item per file)
python phish_analyzer.py mail.eml --authserv-id mx.example.com   # only trust your own server's Authentication-Results
python phish_analyzer.py mail.eml --no-color          # plain text output
```

The exit code is 0 when every file was analyzed and 1 when one of them could not be read or analyzed. The other files are still processed, so one broken mail doesn't stop a batch.

To check one of your own emails you need it as an `.eml` file:
- **Gmail:** open the mail, then ⋮ → *Download message*
- **Thunderbird:** File → Save As → File
- Outlook desktop saves `.msg` files, which this tool can't read yet

Put real emails in a `private/` folder. It's in `.gitignore`, so they never end up on GitHub by accident.

## Example

Output for `samples/phishing_bank.eml`, a fake "your account is blocked" mail from a made-up bank:

```
======================================================================
 phishing_bank.eml
======================================================================
 Subject : Təcili: Hesabınız müvəqqəti bloklanıb
 From    : NovaBank Dəstək <support@novabank.example>
 Reply-To: NovaBank Dəstək <help@novabank-support.example>
 Date    : Mon, 02 Nov 2026 09:13:58 +0400

[ SPF / DKIM / DMARC ]
  SPF    fail
  DKIM   none
  DMARC  fail

[ Route ] first server at the top
  1. vps-4471.cheap-hosting.example [203.0.113.45] -> mx.example.com
  2. mx.example.com [192.0.2.10] -> inbox.example.com

[ Links ] defanged
  hxxp://n0vabank[.]example/login.php?session=8812
     text on screen: hxxps://novabank[.]example/hesabim
  hxxp://203[.]0[.]113[.]45/novabank/verify

[ Attachments ]
  Hesab_melumati.pdf.exe  (application/octet-stream, 76 bytes)
     sha256: 0d6e2ceb52242a76eb6f8b86f3ea1c8423babb18fb1a72f524f7c0dabe9f98fc

[ Findings ]
  +3  links        Link text shows novabank.example but it really goes to n0vabank.example
  +3  domains      n0vabank.example imitates novabank.example (look-alike characters)
  +3  attachments  Hesab_melumati.pdf.exe: .exe files can run code when opened
  +3  content      Pressure / bait words: təcili, bloklan, təsdiq edin, məlumatlarınızı yeniləyin, kart məlumat, 24 saat, şübhəli fəaliyyət
  +2  auth         SPF = fail: the server that sent it is not allowed to send mail for this domain
  +2  auth         DMARC = fail: the From domain isn't backed by SPF/DKIM, typical for spoofing
  +2  sender       Reply-To goes to novabank-support.example, not to novabank.example
  +2  domains      novabank-support.example uses the name 'novabank' but it is not novabank.example
  +2  links        Link goes straight to an IP address (203.0.113.45), real companies use domain names
  +2  attachments  Hesab_melumati.pdf.exe: double extension, Windows hides '.exe' so it looks like a .pdf file
  +1  auth         DKIM = none: doesn't prove who the sender is
  +1  sender       Message-ID was made by vps-4471.cheap-hosting.example, not by novabank.example
  +1  links        Some links use plain http (no encryption)

[ IOCs ] safe to copy into a ticket
  email   support[@]novabank[.]example
  email   help[@]novabank-support[.]example
  ip      203[.]0[.]113[.]45
  domain  n0vabank[.]example
  url     hxxp://n0vabank[.]example/login.php?session=8812
  url     hxxp://203[.]0[.]113[.]45/novabank/verify
  sha256  0d6e2ceb52242a76eb6f8b86f3ea1c8423babb18fb1a72f524f7c0dabe9f98fc

----------------------------------------------------------------------
 Score: 27  ->  HIGH  [####################]
 Looks like phishing. Don't click anything, report it.
======================================================================
```

And for all three samples:

```
Summary
  LOW       0  legit_newsletter.eml
  HIGH     27  phishing_bank.eml
  MEDIUM    6  suspicious_invoice.eml
```

## How the score works

Every finding adds points:

| Finding | Points |
|---|---|
| SPF / DKIM / DMARC = fail | +2 each |
| SPF / DKIM / DMARC = softfail, neutral or none | +1 each |
| Display name is a fake email address | +3 |
| Link text shows a different site than the real link | +3 |
| Look-alike of a trusted domain (swapped letters, 1-2 letters off) | +3 |
| Attachment that can run code | +3 |
| File starts with `MZ` but isn't named like a program | +3 |
| Official sounding name from a free mailbox | +2 |
| Name mentions a known brand but the address doesn't | +2 |
| Reply-To on another domain | +2 |
| Trusted brand name inside another domain | +2 |
| Link to an IP address, punycode domain, `@` trick | +2 each |
| Double extension (`.pdf.exe`) | +2 extra |
| HTML/SVG attachment, Office file with macros | +2 |
| Return-Path or Message-ID from another domain | +1 each |
| Shortener, cheap TLD, very long domain, plain http | +1 each |
| Archive or disk image attachment | +1 |
| Fake `RE:` / `FW:` | +1 |
| Bait words | +1 per word, max 3 |
| VirusTotal says malicious (only with `--vt`) | +5 |

**0-2 = LOW, 3-6 = MEDIUM, 7+ = HIGH**

The numbers are guesses, tuned on the sample emails, so they're definitely not perfect. Weak signals (like a different Return-Path, which newsletters have all the time) only get 1 point, so on their own they can't make a normal email look dangerous.

## VirusTotal (optional)

With `--vt` the tool looks up the SHA256 of every attachment on VirusTotal. **Only the hash is sent, never the file.** Files uploaded to VirusTotal can be downloaded by people with paid accounts, which is bad if it's someone's private document.

1. Make a free account on virustotal.com and copy your API key
2. Put it in an environment variable:
   ```bash
   export VT_API_KEY="your key"      # Linux / macOS
   $env:VT_API_KEY="your key"        # Windows PowerShell
   ```
3. Run `python phish_analyzer.py mail.eml --vt`

The free API allows 4 lookups per minute, so with several attachments the tool waits 15 seconds between them.

## Tests

```bash
python -m unittest discover tests -v     # 36 tests
```

The VirusTotal tests don't use the internet, they fake the answer with `unittest.mock`.

## Things I learned along the way

- **`Received` headers are upside down.** Every server adds its line on top, so the *last* `Received` header is where the mail actually started.
- **`Authentication-Results` can be faked.** A sender can put their own header with `spf=pass` into the mail. Only the one your own mail server adds (the top one) counts, so the tool reads only that one. If your server doesn't add one at all, the top header is the sender's: pass `--authserv-id` with the name your server writes at the start of the header, and every other header is ignored.
- **Passing SPF/DKIM/DMARC doesn't mean the mail is safe.** In `suspicious_invoice.eml` all three pass, because the scammer set them up for their own domain. They only prove the mail really comes from that domain, not that the domain is honest.
- **Python and the Azerbaijani "İ".** `"İ".lower()` gives `i` plus an invisible combining dot (2 characters), and `"I".lower()` gives `i` instead of `ı`. So without a fix, `HESABINIZ` wouldn't match `hesabınız` in the keyword list. `normalize()` in `checks.py` turns every i-like letter into a plain `i` on both sides before comparing.
- **The text of a link means nothing.** `<a href="http://evil.example">https://mybank.az</a>` shows the bank's address but goes somewhere else. That's why the tool compares the two.
- **Windows hides known extensions by default**, so `Hesab_melumati.pdf.exe` shows up as `Hesab_melumati.pdf`. That's why double extensions are such an old trick.

## Limitations

- The base domain is a guess (`mail.bank.az` → `bank.az`). Real tools use the Public Suffix List.
- The look-alike check only knows the domains in `trusted_domains.txt`, and it can give false alarms for real brands with similar names.
- It doesn't open links or check their reputation, on purpose. Only attachment hashes go to VirusTotal.
- It can't read `.msg` (Outlook) files or text inside images (QR code phishing).
- An attacker can simply avoid the words in my keyword list.
- The origin IP in the IOC list is the first public address in the `Received` chain. A sender can add fake `Received` lines below the real ones, so treat it as a lead, not as proof.
- It's a learning project, not a replacement for a real mail gateway or a SOC analyst.

## Ideas for later

- [ ] find QR codes in image attachments ("quishing")
- [ ] read `.msg` files
- [ ] check URLs on URLhaus / VirusTotal
- [ ] a tiny web page where you can drop an `.eml` file
- [ ] read mails straight from a mailbox over IMAP

## About the samples

The three emails in `samples/` are fake, made just for testing. They only use reserved `.example` domains and documentation IP ranges, so nothing in them points to a real server, and the "attachments" are harmless text. If you analyze real phishing, do it in a VM and never open the attachments.

## License

MIT
