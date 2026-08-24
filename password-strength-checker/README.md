# Password Strength Checker

A CLI tool that scores password strength using entropy estimation, a common-password blocklist, and pattern detection (repeats, sequences, letters/digits-only), then gives a rough offline crack-time estimate.

## Usage

```bash
python checker.py "yourpassword"
python checker.py            # prompts interactively, input hidden
```

## Example

```
$ python checker.py password1
Verdict:              WEAK
Entropy estimate:      46.5 bits
Est. offline crack time (fast hash, 1e+10 guesses/sec): instantly
Issues:
  - in the top-common-passwords list

$ python checker.py "Tr0ub4dor&3Zx!kM9"
Verdict:              VERY STRONG
Entropy estimate:      111.7 bits
Est. offline crack time (fast hash, 1e+10 guesses/sec): 132,585,088,539,820.9 centuries
No obvious weak patterns detected.
```

## How it works

- **Entropy**: `length * log2(charset size)` — a ceiling estimate assuming the password is drawn uniformly from whatever character classes it uses (lower/upper/digit/symbol). It does *not* catch a low-entropy password that happens to use a wide charset (e.g. `Aa1!Aa1!` scores higher than it should) — that's what the pattern checks are for.
- **Common-password check**: a small illustrative blocklist. A real implementation should check against a proper breach corpus like [Have I Been Pwned's Pwned Passwords](https://haveibeenpwned.com/Passwords) (k-anonymity API, no need to send the actual password).
- **Crack-time estimate**: assumes an attacker with a fast unsalted-hash offline attack (~10 billion guesses/sec, roughly GPU MD5/SHA1 cracking speed). A properly salted+stretched hash (bcrypt/argon2/scrypt) would be many orders of magnitude slower to attack — this number is meant to illustrate *why* password policy matters, not as a universal constant.

## Note

This is a client-side strength estimator for demonstration/portfolio purposes, not a production-grade auth component. Real systems should combine this kind of check with rate limiting, breach-list lookups, and a slow, salted password hash (argon2id/bcrypt) on the storage side.
