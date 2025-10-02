#!/usr/bin/env python3
"""
Password Strength & Breach Checker (offline-friendly)
=====================================================

This tool evaluates password strength using composition and length rules,
and checks if a password appears in known breach datasets **offline** using:

1) Have I Been Pwned (Pwned Passwords) *range* files (k-anonymity format):
   - Directory containing files named by first 5 SHA-1 hex (uppercase),
     each file listing lines like "<SUFFIX>:<COUNT>".
   - Example: ./pwned_ranges/00000.txt, ./pwned_ranges/5BAA6.txt, etc.

2) A local breach SQLite database you build from plaintext password lists:
   - Use the `index-breaches` subcommand to hash and index a directory
     of newline-delimited password dumps (UTF-8 text files).

USAGE EXAMPLES
--------------
# Check one password interactively (safer than passing on CLI):
$ python pw_audit.py check --pwned-range-dir ./pwned_ranges --breach-db ./breach_pw.sqlite
Password: <typing is hidden>

# Index a folder of plaintext password breach files into SQLite once:
$ python pw_audit.py index-breaches --breach-dir ./breach_plaintext_dir --db ./breach_pw.sqlite

# Check a list of passwords from a file (one per line):
$ python pw_audit.py check-file passwords.txt --pwned-range-dir ./pwned_ranges --breach-db ./breach_pw.sqlite

SECURITY NOTES
--------------
- Avoid putting secrets directly on the command line or in shell history.
  Prefer the interactive prompt or `check-file`.
- The Pwned Passwords dataset is *SHA-1 of plaintext passwords* with counts.
  This script never uploads; lookups are strictly local.
- The SQLite breach DB stores only SHA-1(password) values, not plaintext.

Dependencies: Standard Library only (no external packages).
"""
from __future__ import annotations

import argparse
import getpass
import hashlib
import os
import sqlite3
import sys
import textwrap
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional, Tuple, List

# ------------------------------
# Password composition/strength
# ------------------------------
@dataclass
class StrengthResult:
    length: int
    has_lower: bool
    has_upper: bool
    has_digit: bool
    has_special: bool
    unique_chars: int
    repeats_penalty: int
    length_score: int
    class_score: int
    entropy_guess_bits: float
    total_score: int  # 0..10
    verdict: str
    suggestions: List[str]

SPECIAL_CHARS = set("!@#$%^&*()-_=+[{]}\\|;:'\",<.>/?`~")


def estimate_entropy_bits(pw: str) -> float:
    """Rough Shannon-entropy-ish guess based on char sets present and length.
    Not rigorous. For guidance only.
    """
    if not pw:
        return 0.0
    charset = 0
    if any(c.islower() for c in pw):
        charset += 26
    if any(c.isupper() for c in pw):
        charset += 26
    if any(c.isdigit() for c in pw):
        charset += 10
    if any(c in SPECIAL_CHARS for c in pw):
        charset += len(SPECIAL_CHARS)
    # Fallback if only uncommon unicode etc.
    if charset == 0:
        charset = min(128, len({c for c in pw}))
    return len(pw) * (charset or 1).bit_length()


def score_password(pw: str) -> StrengthResult:
    L = len(pw)
    has_lower = any(c.islower() for c in pw)
    has_upper = any(c.isupper() for c in pw)
    has_digit = any(c.isdigit() for c in pw)
    has_special = any(c in SPECIAL_CHARS for c in pw)

    # Length score (0..4)
    if L >= 20:
        length_score = 4
    elif L >= 16:
        length_score = 3
    elif L >= 12:
        length_score = 2
    elif L >= 8:
        length_score = 1
    else:
        length_score = 0

    # Character class score (0..4)
    class_score = sum([has_lower, has_upper, has_digit, has_special])

    unique_chars = len(set(pw))
    repeats_penalty = 0
    if L > 0 and unique_chars / max(1, L) < 0.6:
        repeats_penalty = 1

    entropy_guess_bits = estimate_entropy_bits(pw)

    # Base total (0..8) minus penalty, then clamp and add entropy bonus.
    base_total = max(0, min(8, length_score + class_score - repeats_penalty))
    # Entropy nudge: +0..2 based on rough thresholds
    entropy_bonus = 0
    if entropy_guess_bits >= 70:
        entropy_bonus = 2
    elif entropy_guess_bits >= 50:
        entropy_bonus = 1
    total = max(0, min(10, base_total + entropy_bonus))

    if total <= 3:
        verdict = "Very Weak"
    elif total <= 5:
        verdict = "Weak"
    elif total <= 7:
        verdict = "Moderate"
    elif total <= 8:
        verdict = "Strong"
    else:
        verdict = "Very Strong"

    suggestions = []
    if L < 16:
        suggestions.append("Increase length to 16+ characters (prefer passphrases).")
    if not has_lower:
        suggestions.append("Include at least one lowercase letter.")
    if not has_upper:
        suggestions.append("Include at least one uppercase letter.")
    if not has_digit:
        suggestions.append("Include at least one digit.")
    if not has_special:
        suggestions.append("Include at least one special character.")
    if repeats_penalty:
        suggestions.append("Avoid heavy repetition or very limited character variety.")

    return StrengthResult(
        length=L,
        has_lower=has_lower,
        has_upper=has_upper,
        has_digit=has_digit,
        has_special=has_special,
        unique_chars=unique_chars,
        repeats_penalty=repeats_penalty,
        length_score=length_score,
        class_score=class_score,
        entropy_guess_bits=entropy_guess_bits,
        total_score=total,
        verdict=verdict,
        suggestions=suggestions,
    )


# ----------------------------------------
# Pwned Passwords (range-file) local check
# ----------------------------------------

def sha1_hex_upper(data: bytes) -> str:
    return hashlib.sha1(data).hexdigest().upper()


def pwned_local_lookup(password: str, range_dir: Path, ext: str = ".txt") -> Optional[int]:
    """Check password against local Pwned Passwords *range* files.

    - Computes SHA-1(password) uppercase hex.
    - Opens file <range_dir>/<first5>.txt (or <ext>)
    - Searches for a line "<SUFFIX>:<COUNT>" (case-sensitive, suffix uppercase)
    - Returns count if found; otherwise None.
    """
    h = sha1_hex_upper(password.encode("utf-8"))
    prefix, suffix = h[:5], h[5:]
    fname = range_dir / f"{prefix}{ext}"
    if not fname.exists():
        return None
    try:
        with fname.open("r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line or ":" not in line:
                    continue
                suf, count = line.split(":", 1)
                if suf.upper() == suffix:
                    try:
                        return int(count)
                    except ValueError:
                        return 0
    except OSError:
        return None
    return None


# ----------------------------------
# Local Breach DB (SQLite) utilities
# ----------------------------------
DB_SCHEMA = """
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS pw (
    sha1 TEXT PRIMARY KEY
);
"""


def db_connect(db_path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA synchronous=NORMAL;")
    conn.execute("PRAGMA temp_store=MEMORY;")
    return conn


def db_init(conn: sqlite3.Connection) -> None:
    conn.executescript(DB_SCHEMA)
    conn.commit()


def db_add_hashes(conn: sqlite3.Connection, hashes: Iterable[str], batch: int = 10000) -> int:
    cur = conn.cursor()
    total = 0
    buf: List[Tuple[str]] = []
    for h in hashes:
        buf.append((h,))
        if len(buf) >= batch:
            cur.executemany("INSERT OR IGNORE INTO pw(sha1) VALUES(?)", buf)
            conn.commit()
            total += len(buf)
            buf.clear()
    if buf:
        cur.executemany("INSERT OR IGNORE INTO pw(sha1) VALUES(?)", buf)
        conn.commit()
        total += len(buf)
    return total


def db_contains(conn: sqlite3.Connection, sha1_hex: str) -> bool:
    cur = conn.cursor()
    cur.execute("SELECT 1 FROM pw WHERE sha1=? LIMIT 1", (sha1_hex,))
    return cur.fetchone() is not None


# ----------------------
# CLI helper subcommands
# ----------------------

def cmd_index_breaches(args: argparse.Namespace) -> int:
    src_dir = Path(args.breach_dir)
    db_path = Path(args.db)
    if not src_dir.is_dir():
        print(f"[!] breach dir not found: {src_dir}", file=sys.stderr)
        return 2
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = db_connect(db_path)
    db_init(conn)
    print(f"[*] Indexing plaintext passwords from {src_dir} into {db_path} (SHA-1 only)...")
    count_in = 0
    def gen_hashes() -> Iterable[str]:
        nonlocal count_in
        for root, _, files in os.walk(src_dir):
            for name in files:
                p = Path(root) / name
                try:
                    with p.open("r", encoding="utf-8", errors="ignore") as f:
                        for line in f:
                            pw = line.rstrip("\n\r")
                            if not pw:
                                continue
                            count_in += 1
                            yield sha1_hex_upper(pw.encode("utf-8"))
                except OSError:
                    continue
    total_added = db_add_hashes(conn, gen_hashes())
    print(f"[*] Scanned {count_in} lines; inserted/seen {total_added} hashes into DB.")
    return 0


def describe_strength(sr: StrengthResult) -> str:
    bullet = []
    bullet.append(f"Length: {sr.length} (unique chars: {sr.unique_chars})")
    checks = [
        (sr.has_lower, "lowercase"),
        (sr.has_upper, "uppercase"),
        (sr.has_digit, "digit"),
        (sr.has_special, "special"),
    ]
    present = ", ".join([name for ok, name in checks if ok]) or "none"
    missing = ", ".join([name for ok, name in checks if not ok]) or "none"
    bullet.append(f"Classes present: {present}; missing: {missing}")
    bullet.append(f"Entropy guess: ~{sr.entropy_guess_bits:.1f} bits")
    bullet.append(f"Score: {sr.total_score}/10 → {sr.verdict}")
    if sr.suggestions:
        bullet.append("Suggestions: " + " ".join(sr.suggestions))
    return "\n".join(" - " + b for b in bullet)


def cmd_check(args: argparse.Namespace) -> int:
    pw = args.password
    if pw is None:
        pw = getpass.getpass("Password: ")
    sr = score_password(pw)
    print(describe_strength(sr))

    # Pwned range check
    if args.pwned_range_dir:
        count = pwned_local_lookup(pw, Path(args.pwned_range_dir), ext=args.pwned_range_ext)
        if count is None:
            print(" - Pwned Passwords: prefix file not found or not matched (no hit).")
        elif count > 0:
            print(f" - Pwned Passwords: FOUND with {count} occurrences — DO NOT USE.")
        else:
            print(" - Pwned Passwords: not found in range file.")

    # Local breach DB check
    if args.breach_db:
        dbp = Path(args.breach_db)
        if dbp.exists():
            conn = db_connect(dbp)
            h = sha1_hex_upper(pw.encode("utf-8"))
            if db_contains(conn, h):
                print(" - Local Breach DB: FOUND (hash present) — treat as compromised.")
            else:
                print(" - Local Breach DB: not present.")
        else:
            print(" - Local Breach DB: database file not found.")

    return 0


def cmd_check_file(args: argparse.Namespace) -> int:
    src = Path(args.file)
    if not src.exists():
        print(f"[!] file not found: {src}", file=sys.stderr)
        return 2
    pdir = Path(args.pwned_range_dir) if args.pwned_range_dir else None
    dbp = Path(args.breach_db) if args.breach_db else None
    if dbp and not dbp.exists():
        print("[!] breach DB does not exist; run index-breaches first.", file=sys.stderr)
    with src.open("r", encoding="utf-8", errors="ignore") as f:
        for i, line in enumerate(f, 1):
            pw = line.rstrip("\n\r")
            if not pw:
                continue
            print(f"\n=== Password #{i} ===")
            sr = score_password(pw)
            print(describe_strength(sr))
            if pdir:
                count = pwned_local_lookup(pw, pdir, ext=args.pwned_range_ext)
                if count is None:
                    print(" - Pwned Passwords: prefix file not found or not matched (no hit).")
                elif count > 0:
                    print(f" - Pwned Passwords: FOUND with {count} occurrences — DO NOT USE.")
                else:
                    print(" - Pwned Passwords: not found in range file.")
            if dbp and dbp.exists():
                conn = db_connect(dbp)
                h = sha1_hex_upper(pw.encode("utf-8"))
                if db_contains(conn, h):
                    print(" - Local Breach DB: FOUND (hash present) — treat as compromised.")
                else:
                    print(" - Local Breach DB: not present.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Password strength and offline breach checks",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    p_index = sub.add_parser("index-breaches", help="Index plaintext breach files into SQLite (SHA-1 hashes only)")
    p_index.add_argument("--breach-dir", required=True, help="Directory of plaintext password lists (newline-delimited)")
    p_index.add_argument("--db", required=True, help="SQLite DB path to create/update")
    p_index.set_defaults(func=cmd_index_breaches)

    p_check = sub.add_parser("check", help="Check a single password (interactive by default)")
    p_check.add_argument("--password", help="Password literal (avoid; prefer interactive)")
    p_check.add_argument("--pwned-range-dir", help="Directory of Pwned Passwords range files (first5).txt")
    p_check.add_argument("--pwned-range-ext", default=".txt", help="Extension for range files (default: .txt)")
    p_check.add_argument("--breach-db", help="SQLite DB built via index-breaches")
    p_check.set_defaults(func=cmd_check)

    p_file = sub.add_parser("check-file", help="Check every line in a file as a password")
    p_file.add_argument("file", help="Text file with one password per line")
    p_file.add_argument("--pwned-range-dir", help="Directory of Pwned Passwords range files (first5).txt")
    p_file.add_argument("--pwned-range-ext", default=".txt", help="Extension for range files (default: .txt)")
    p_file.add_argument("--breach-db", help="SQLite DB built via index-breaches")
    p_file.set_defaults(func=cmd_check_file)

    return p


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        print("\n[!] Aborted.")
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
