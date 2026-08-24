#!/usr/bin/env python3
"""
CVSS v3.1 base score calculator: implements the official formula from
the FIRST.org CVSS v3.1 specification, taking a standard vector string
and producing the base score + severity rating.

Usage:
  python cvss.py "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
"""

import argparse
import sys

# Metric value -> numeric weight, per CVSS v3.1 spec section 7.
AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
AC = {"L": 0.77, "H": 0.44}
PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.5}
UI = {"N": 0.85, "R": 0.62}
CIA = {"H": 0.56, "L": 0.22, "N": 0.0}

REQUIRED_METRICS = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"]


def parse_vector(vector):
    vector = vector.strip()
    if vector.upper().startswith("CVSS:3.1/"):
        vector = vector[len("CVSS:3.1/"):]
    elif vector.upper().startswith("CVSS:3.0/"):
        vector = vector[len("CVSS:3.0/"):]

    metrics = {}
    for part in vector.split("/"):
        if not part:
            continue
        if ":" not in part:
            raise ValueError(f"Malformed metric segment: '{part}'")
        key, value = part.split(":", 1)
        metrics[key.upper()] = value.upper()

    missing = [m for m in REQUIRED_METRICS if m not in metrics]
    if missing:
        raise ValueError(f"Missing required metric(s): {', '.join(missing)}")

    return metrics


def roundup(value):
    """CVSS spec's custom round-up-to-1-decimal, not plain rounding."""
    int_value = round(value * 100000)
    if int_value % 10000 == 0:
        return int_value / 100000
    return (int_value // 10000 + 1) / 10.0


def base_score(metrics):
    scope_changed = metrics["S"] == "C"

    iss = 1 - ((1 - CIA[metrics["C"]]) * (1 - CIA[metrics["I"]]) * (1 - CIA[metrics["A"]]))

    if not scope_changed:
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)

    pr_table = PR_CHANGED if scope_changed else PR_UNCHANGED
    exploitability = 8.22 * AV[metrics["AV"]] * AC[metrics["AC"]] * pr_table[metrics["PR"]] * UI[metrics["UI"]]

    if impact <= 0:
        return 0.0, impact, exploitability

    if not scope_changed:
        score = roundup(min(impact + exploitability, 10))
    else:
        score = roundup(min(1.08 * (impact + exploitability), 10))

    return score, impact, exploitability


def severity(score):
    if score == 0.0:
        return "None"
    if score < 4.0:
        return "Low"
    if score < 7.0:
        return "Medium"
    if score < 9.0:
        return "High"
    return "Critical"


def main():
    parser = argparse.ArgumentParser(description="CVSS v3.1 base score calculator")
    parser.add_argument("vector", help='e.g. "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"')
    args = parser.parse_args()

    try:
        metrics = parse_vector(args.vector)
        score, impact, exploitability = base_score(metrics)
    except (ValueError, KeyError) as e:
        print(f"Invalid CVSS vector: {e}", file=sys.stderr)
        sys.exit(1)

    print(f"\nVector:         {args.vector}")
    print(f"Base score:      {score} ({severity(score)})")
    print(f"Impact subscore: {round(impact, 2)}")
    print(f"Exploitability:  {round(exploitability, 2)}")


if __name__ == "__main__":
    main()
