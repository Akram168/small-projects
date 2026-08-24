# Hash Identifier

Given a hash string pulled from a log, memory dump, or credential leak, guesses what algorithm produced it — by length for raw hex digests, and by distinctive prefix for structured formats like bcrypt/argon2/shadow-file hashes. The "what even is this string" first step before deciding where to look it up or how to attempt cracking it (with proper authorization, e.g. hashcat during a pentest).

## Usage

```bash
python identify.py 5f4dcc3b5aa765d61d8327deb882cf99
python identify.py --file hashes.txt
```

## Example

```
$ python identify.py 5f4dcc3b5aa765d61d8327deb882cf99
  Possible: MD5, NTLM, MD4
  Reason:   hex string, 32 characters

$ python identify.py e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
  Possible: SHA-256, SHA3-256, BLAKE2s
  Reason:   hex string, 64 characters

$ python identify.py '$2b$12$KIXQnJz8YfN7B3vQeqJhZeR7YQoZ8mF5xJ8vQeqJhZeR7YQoZ8mF5'
  Possible: bcrypt
  Reason:   distinctive prefix format
```

## How it works

- **Structured formats first**: bcrypt (`$2a$`/`$2b$`/`$2y$`), argon2 (`$argon2id$` etc.), and glibc shadow-file hashes (`$1$`/`$5$`/`$6$`) all self-identify via an unambiguous prefix — checked before anything else.
- **Raw hex digests**: identified by length alone, since that's the only signal a bare hex string carries. Multiple algorithms share the same output length (MD5/NTLM/MD4 are all 32 hex chars) — the tool reports every plausible match rather than guessing one, since length alone can't disambiguate further.

## Limitations

Length-based matching is inherently ambiguous where algorithms collide (this is disclosed in the output, not hidden). It also can't distinguish a *salted* hash from an unsalted one when both produce the same raw output format — that context (where the hash came from, what system produced it) usually has to come from the analyst, not the string itself.
