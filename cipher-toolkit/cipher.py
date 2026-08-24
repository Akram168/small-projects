#!/usr/bin/env python3
"""
Classical cipher toolkit: Caesar, Vigenere, and XOR -- encode, decode,
and (for Caesar) brute-force every shift with an English-likeness score.

These are NOT secure ciphers. They're included for learning how classical
substitution/stream ciphers work and why frequency analysis breaks them.
For anything that actually needs to be secure, use the `cryptography`
library's Fernet or AES-GCM (see the encrypted-notes-cli project).

Usage:
  python cipher.py caesar encode "attack at dawn" --shift 3
  python cipher.py caesar decode "dwwdfn dw gdzq" --shift 3
  python cipher.py caesar crack "dwwdfn dw gdzq"
  python cipher.py vigenere encode "attack at dawn" --key lemon
  python cipher.py vigenere decode "lxfopv ef rnhr" --key lemon
  python cipher.py xor encode "secret" --key "k1"
  python cipher.py xor decode <hex> --key "k1"
"""

import argparse
import string

ALPHABET = string.ascii_lowercase

# Rough relative frequency of letters in English text (%), used to score
# candidate plaintexts during Caesar brute-forcing.
ENGLISH_FREQ = {
    'a': 8.2, 'b': 1.5, 'c': 2.8, 'd': 4.3, 'e': 12.7, 'f': 2.2, 'g': 2.0,
    'h': 6.1, 'i': 7.0, 'j': 0.15, 'k': 0.77, 'l': 4.0, 'm': 2.4, 'n': 6.7,
    'o': 7.5, 'p': 1.9, 'q': 0.095, 'r': 6.0, 's': 6.3, 't': 9.1, 'u': 2.8,
    'v': 0.98, 'w': 2.4, 'x': 0.15, 'y': 2.0, 'z': 0.074,
}


def caesar_shift_char(c, shift):
    if c.islower():
        return ALPHABET[(ALPHABET.index(c) + shift) % 26]
    if c.isupper():
        return ALPHABET[(ALPHABET.index(c.lower()) + shift) % 26].upper()
    return c


def caesar_encode(text, shift):
    return "".join(caesar_shift_char(c, shift) for c in text)


def caesar_decode(text, shift):
    return caesar_encode(text, -shift)


def english_score(text):
    letters = [c.lower() for c in text if c.isalpha()]
    if not letters:
        return 0.0
    score = 0.0
    for c in letters:
        score += ENGLISH_FREQ.get(c, 0.0)
    return score / len(letters)


def caesar_crack(text, top_n=3):
    candidates = []
    for shift in range(26):
        decoded = caesar_decode(text, shift)
        candidates.append((shift, english_score(decoded), decoded))
    candidates.sort(key=lambda c: c[1], reverse=True)
    return candidates[:top_n]


def vigenere_shift_char(c, key_char, decode=False):
    if not c.isalpha():
        return c
    shift = ALPHABET.index(key_char.lower())
    if decode:
        shift = -shift
    return caesar_shift_char(c, shift)


def vigenere_transform(text, key, decode=False):
    if not key or not key.isalpha():
        raise ValueError("Vigenere key must be a non-empty alphabetic string")
    result = []
    key_index = 0
    for c in text:
        if c.isalpha():
            key_char = key[key_index % len(key)]
            result.append(vigenere_shift_char(c, key_char, decode=decode))
            key_index += 1
        else:
            result.append(c)
    return "".join(result)


def xor_transform(data_bytes, key_bytes):
    return bytes(b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(data_bytes))


def main():
    parser = argparse.ArgumentParser(description="Classical cipher toolkit")
    sub = parser.add_subparsers(dest="cipher", required=True)

    p_caesar = sub.add_parser("caesar")
    caesar_sub = p_caesar.add_subparsers(dest="mode", required=True)
    for mode in ("encode", "decode"):
        p = caesar_sub.add_parser(mode)
        p.add_argument("text")
        p.add_argument("--shift", type=int, required=True)
    p_crack = caesar_sub.add_parser("crack")
    p_crack.add_argument("text")

    p_vig = sub.add_parser("vigenere")
    vig_sub = p_vig.add_subparsers(dest="mode", required=True)
    for mode in ("encode", "decode"):
        p = vig_sub.add_parser(mode)
        p.add_argument("text")
        p.add_argument("--key", required=True)

    p_xor = sub.add_parser("xor")
    xor_sub = p_xor.add_subparsers(dest="mode", required=True)
    p_xe = xor_sub.add_parser("encode")
    p_xe.add_argument("text")
    p_xe.add_argument("--key", required=True)
    p_xd = xor_sub.add_parser("decode")
    p_xd.add_argument("hex_text")
    p_xd.add_argument("--key", required=True)

    args = parser.parse_args()

    if args.cipher == "caesar":
        if args.mode == "encode":
            print(caesar_encode(args.text, args.shift))
        elif args.mode == "decode":
            print(caesar_decode(args.text, args.shift))
        elif args.mode == "crack":
            print("Top candidates (shift, English-likeness score, decoded text):")
            for shift, score, decoded in caesar_crack(args.text):
                print(f"  shift={shift:2d}  score={score:5.2f}  {decoded}")

    elif args.cipher == "vigenere":
        if args.mode == "encode":
            print(vigenere_transform(args.text, args.key, decode=False))
        elif args.mode == "decode":
            print(vigenere_transform(args.text, args.key, decode=True))

    elif args.cipher == "xor":
        key_bytes = args.key.encode()
        if args.mode == "encode":
            result = xor_transform(args.text.encode(), key_bytes)
            print(result.hex())
        elif args.mode == "decode":
            data = bytes.fromhex(args.hex_text)
            result = xor_transform(data, key_bytes)
            print(result.decode(errors="replace"))


if __name__ == "__main__":
    main()
