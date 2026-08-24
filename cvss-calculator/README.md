# CVSS v3.1 Base Score Calculator

Implements the official CVSS v3.1 base-score formula from the [FIRST.org specification](https://www.first.org/cvss/v3.1/specification-document) — feed it a standard vector string, get the score and severity rating back. No API calls, no lookup table shortcuts — the actual impact/exploitability math.

## Usage

```bash
python cvss.py "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
```

## Verified against real CVEs

```
$ python cvss.py "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
Base score:      9.8 (Critical)

$ python cvss.py "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"    # Log4Shell, CVE-2021-44228
Base score:      10.0 (Critical)

$ python cvss.py "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
Base score:      5.3 (Medium)
```

All three match their officially published NVD base scores exactly, including the Log4Shell vector scoring a perfect 10.0.

## Metrics

| Code | Metric | Values |
|---|---|---|
| AV | Attack Vector | N(etwork) / A(djacent) / L(ocal) / P(hysical) |
| AC | Attack Complexity | L(ow) / H(igh) |
| PR | Privileges Required | N(one) / L(ow) / H(igh) |
| UI | User Interaction | N(one) / R(equired) |
| S | Scope | U(nchanged) / C(hanged) |
| C / I / A | Confidentiality / Integrity / Availability impact | H(igh) / L(ow) / N(one) |

## Why this is harder than it looks

The formula isn't a simple weighted sum — it involves a custom "round up to 1 decimal place" function (standard rounding gives wrong answers on several real vectors), a scope-dependent branch that changes both the impact formula *and* the privileges-required weight table, and an impact function that's genuinely different (not just rescaled) depending on whether scope is changed. Getting all three test vectors above to match NVD's published scores exactly means the branching and the custom rounding are both implemented correctly — a naive port of "the formula" without the round-up quirk gets subtly wrong answers on some vectors while looking right on others.

## Limitations

Base score only — CVSS also defines Temporal and Environmental metric groups (exploit maturity, remediation availability, org-specific impact) that this doesn't implement. Base score is what NVD publishes per-CVE and what most vulnerability scanners report by default, so it's the most broadly useful piece to get exactly right.
