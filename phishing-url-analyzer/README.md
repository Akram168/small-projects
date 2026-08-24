# Phishing URL Analyzer

A rule-based heuristic scorer that flags URLs likely to be phishing links: IP-address hosts, punycode/homograph domains, brand names stuffed into a subdomain instead of the real root domain, URL shorteners, suspicious TLDs, `@`-in-authority bait-and-switch, and credential-bait keywords.

## Usage

```bash
python analyzer.py "http://example.com/path"
python analyzer.py --file urls.txt   # one URL per line
```

## Example

```
$ python analyzer.py "http://paypal.secure-verify-login.com.xn--80ak6aa92e.info/account"
URL:  http://paypal.secure-verify-login.com.xn--80ak6aa92e.info/account
Risk: HIGH  (score 100/100)
  - hostname uses punycode (xn--) -- possible homograph/lookalike attack
  - unusually many hyphens in hostname (common in typosquat domains)
  - unusually many subdomain levels
  - uses a TLD commonly abused in phishing campaigns (.info)
  - brand name 'paypal' appears in hostname but not in the actual root domain (xn--80ak6aa92e.info) -- likely impersonation
  - hostname contains urgency/credential bait keywords

$ python analyzer.py "https://github.com/juice-shop/juice-shop"
URL:  https://github.com/juice-shop/juice-shop
Risk: LOW  (score 0/100)
  - no suspicious features detected
```

## How it works

Each feature adds points to a 0-100 risk score:

| Feature | Why it matters |
|---|---|
| Raw IP as hostname | Legit brands don't link directly to IPs |
| Punycode (`xn--`) | Used for homograph attacks (lookalike Unicode domains) |
| Brand name in hostname but not in the root domain | `paypal.secure-login.com` is *not* paypal.com — the brand is bait, not the actual owner |
| URL shortener | Hides the real destination until you click |
| Suspicious/cheap TLD | `.info`, `.top`, `.click` etc. are disproportionately used in phishing (cheap, low registration friction) |
| `@` in the authority part | Everything before `@` is ignored by the browser — `real-bank.com@evil.com` goes to `evil.com` |
| Excess hyphens / subdomain depth | Typosquatting and lookalike-domain patterns |
| Long URL | Obfuscation via length/complexity |
| Urgency keywords (`secure-`, `verify-`, `confirm-`) | Classic phishing pretext |

## Limitations

This is a **heuristic** tool for demonstration, not a phishing detector you should rely on in production. It has no access to domain age/WHOIS, TLS certificate details, reputation feeds, or page content — a real anti-phishing pipeline (e.g. Google Safe Browsing, PhishTank) combines dozens of these signals with live threat intel and ML classifiers trained on much larger feature sets.
