# Security Headers Checker

Fetches a URL and grades its response for the six most impactful security-relevant HTTP headers, explaining what each one defends against when it's missing. The kind of quick external recon step a SOC/appsec review starts with.

## Usage

```bash
python checker.py https://example.com
```

## Example (real, live)

```
$ python checker.py https://github.com

https://github.com  (HTTP 200)
Grade: B  (5/6 security headers present)

[PRESENT] Strict-Transport-Security
           value: max-age=31536000; includeSubdomains; preload
[PRESENT] Content-Security-Policy
           value: default-src 'none'; base-uri 'self'; ...
[PRESENT] X-Content-Type-Options
           value: nosniff
[PRESENT] X-Frame-Options
           value: deny
[PRESENT] Referrer-Policy
           value: origin-when-cross-origin, strict-origin-when-cross-origin
[MISSING] Permissions-Policy
           why it matters: Explicitly disables browser features (camera, geolocation, etc.) the page doesn't need, shrinking what an XSS could abuse.
```

Even GitHub — about as hardened a target as you'll find — doesn't hit a perfect score, which is a fair reflection of reality: `Permissions-Policy` is newer and less universally adopted than the other five checks here.

## What's checked

| Header | Defends against |
|---|---|
| `Strict-Transport-Security` | HTTP downgrade / SSL-stripping on first visit |
| `Content-Security-Policy` | XSS actually executing, even if injected |
| `X-Content-Type-Options` | MIME-sniffing turning a data upload into executable content |
| `X-Frame-Options` | Clickjacking via iframe embedding |
| `Referrer-Policy` | URL/path leakage to third parties via the `Referer` header |
| `Permissions-Policy` | Unused browser features (camera, geolocation, ...) being available to an XSS payload at all |

## Limitations

This checks *presence* and shows the raw value — it doesn't fully validate CSP policy quality (a CSP with `script-src *` is present but nearly useless), doesn't check TLS configuration/cipher strength, and doesn't crawl beyond the single URL given. Tools like Mozilla Observatory or securityheaders.com do a deeper version of this same idea — this is the "understand what's actually being checked and why" version.
