# Cipher Toolkit

Classical ciphers (Caesar, Vigenère, XOR) with encode/decode and Caesar brute-forcing via English-frequency scoring. Built to understand how classical substitution/stream ciphers work — and why they're broken by frequency analysis.

> **These are not secure ciphers.** They're for learning cryptographic history and cryptanalysis technique. For anything that needs real confidentiality, use a vetted library (see [`encrypted-notes-cli`](../../big-projects/encrypted-notes-cli) for a proper AES/Fernet example) — never roll your own crypto for production use.

## Usage

```bash
# Caesar
python cipher.py caesar encode "attack at dawn" --shift 3
python cipher.py caesar decode "dwwdfn dw gdzq" --shift 3
python cipher.py caesar crack "dwwdfn dw gdzq"      # no key needed

# Vigenere
python cipher.py vigenere encode "attackatdawn" --key lemon
python cipher.py vigenere decode "lxfopvefrnhr" --key lemon

# XOR (stream cipher, outputs/reads hex)
python cipher.py xor encode "secret message" --key "k1"
python cipher.py xor decode <hex-output> --key "k1"
```

## Example: cracking a Caesar cipher with no known key

```
$ python cipher.py caesar crack "dwwdfn dw gdzq"
Top candidates (shift, English-likeness score, decoded text):
  shift=25  score= 6.75  exxego ex hear
  shift=18  score= 6.45  leelnv le olhy
  shift= 3  score= 6.42  attack at dawn
```

The scorer averages each candidate's per-letter English-frequency weight — a simplified metric, not true chi-squared distance against the reference distribution. On short ciphertext it doesn't always rank the real plaintext #1 (as above, where the correct answer is 3rd) — showing the top few candidates and eyeballing which one reads as real English is standard practice for this technique, and it's a fair demonstration of both the power *and* the limits of frequency analysis on short messages.

## Why these ciphers are broken

- **Caesar**: only 26 possible keys — trivially brute-forced (see above), and even without brute force, letter-frequency analysis alone recovers the shift on any decent-length ciphertext.
- **Vigenère**: a repeating-key polyalphabetic cipher. Once the key length is found (Kasiski examination / index of coincidence), it reduces to N independent Caesar ciphers — one per key-length residue.
- **XOR with a short repeating key**: identical weakness to Vigenère — repeat the key long enough and it's a many-time pad, breakable the same way. A XOR "one-time pad" is only secure if the key is truly random, at least as long as the message, and *never reused* — which is exactly why it's impractical for real use (key distribution/reuse is the whole problem OTPs can't solve at scale).
