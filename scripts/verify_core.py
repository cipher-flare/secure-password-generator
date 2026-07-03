"""
verify_core.py
==============
No-deps smoke test for password_core.py.

Exercises the bits of password_core.py the test suite covers, but with a
single ``python scripts/verify_core.py`` invocation and zero third-party
dependencies (no pytest). Useful for a quick CI sanity check, a fresh
clone, or a teaching demo where you don't want to install pytest first.

Exit code 0 on success, 1 on any failure.
"""

from __future__ import annotations

import math
import os
import sys
import traceback

# Allow running this script directly (``python scripts/verify_core.py``)
# without installing the project. Insert the repo root onto sys.path.
_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(_HERE))

import password_core as pc


# ---------------------------------------------------------------------------
# Tiny harness
# ---------------------------------------------------------------------------
def check(cond, msg):
    if not cond:
        print(f"  FAIL: {msg}")
        raise AssertionError(msg)
    print(f"  ok  : {msg}")


def section(title):
    print(f"\n[{title}]")


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------
def verify_validate():
    section("validate_inputs")

    ok, length, count, err = pc.validate_inputs(16, 1, ["lowercase"])
    check(ok and err == "" and length == 16 and count == 1, "valid minimal input")

    ok, length, count, err = pc.validate_inputs("20", "3", ["lowercase"])
    check(ok and length == 20 and count == 3, "string ints are coerced")

    ok, length, count, err = pc.validate_inputs(3, 1, ["lowercase"])
    check(not ok and "at least" in err, "length below min rejected")

    ok, _, _, err = pc.validate_inputs(16, 51, ["lowercase"])
    check(not ok and "exceed" in err, "count above max rejected")

    ok, _, _, err = pc.validate_inputs("abc", 1, ["lowercase"])
    check(not ok and "whole number" in err, "non-integer length rejected")

    ok, _, _, err = pc.validate_inputs(16, 1, [])
    check(not ok and "category" in err, "empty categories rejected")


# ---------------------------------------------------------------------------
# Generation — category guarantee
# ---------------------------------------------------------------------------
def verify_generation():
    section("generate_password category guarantee")

    cats = ["uppercase", "lowercase", "numbers", "special"]
    for length in [4, 8, 12, 16, 32, 64, 128]:
        pwd = pc.generate_password(length, cats)
        check(len(pwd) == length, f"length {length} preserved")
        check(any(c in pc.CHAR_SETS["uppercase"] for c in pwd), "uppercase present")
        check(any(c in pc.CHAR_SETS["lowercase"] for c in pwd), "lowercase present")
        check(any(c in pc.CHAR_SETS["numbers"] for c in pwd), "numbers present")
        check(any(c in pc.CHAR_SETS["special"] for c in pwd), "special present")

    # Single category, length 4
    pwd = pc.generate_password(4, ["lowercase"])
    check(len(pwd) == 4 and all(c in pc.CHAR_SETS["lowercase"] for c in pwd),
          "single-category output stays in pool")

    # Strict mode is a no-op when fewer than 4 categories are selected
    pwd = pc.generate_password(16, ["lowercase", "numbers"], strict=True)
    check(len(pwd) == 16, "strict= works with two categories")

    # Strict + all four categories + length 16
    pwd = pc.generate_password(16, cats, strict=True)
    check(len(pwd) == 16, "strict= works with four categories and length 16")

    # avoid_ambiguous does not introduce any ambiguous character
    pwd = pc.generate_password(64, cats, avoid_ambiguous=True)
    check(not any(c in pc.AMBIGUOUS_CHARS for c in pwd),
          "avoid_ambiguous strips every ambiguous char")

    # Errors
    try:
        pc.generate_password(2, ["uppercase", "lowercase", "numbers"])
        check(False, "length < category count must raise")
    except ValueError:
        check(True, "length < category count raises ValueError")

    try:
        pc.generate_password(16, [])
        check(False, "empty categories must raise")
    except ValueError:
        check(True, "empty categories raises ValueError")


# ---------------------------------------------------------------------------
# pool_size
# ---------------------------------------------------------------------------
def verify_pool_size():
    section("pool_size")

    check(pc.pool_size(["lowercase"]) == 26, "lowercase pool == 26")
    check(pc.pool_size(["uppercase", "lowercase"]) == 52, "alpha pool == 52")
    check(pc.pool_size(["uppercase", "lowercase", "numbers"]) == 62, "alnum pool == 62")
    full = pc.pool_size(["uppercase", "lowercase", "numbers", "special"])
    filtered = pc.pool_size(
        ["uppercase", "lowercase", "numbers", "special"], avoid_ambiguous=True
    )
    check(full > filtered, "avoid_ambiguous reduces pool")
    check(filtered == full - sum(1 for c in "".join(pc.CHAR_SETS.values()) if c in pc.AMBIGUOUS_CHARS),
          "avoid_ambiguous drops exactly the ambiguous chars")


# ---------------------------------------------------------------------------
# Entropy + crack time
# ---------------------------------------------------------------------------
def verify_entropy_and_crack_time():
    section("entropy and crack-time formatter")

    pool = pc.pool_size(["uppercase", "lowercase", "numbers", "special"])
    e = pc.calculate_entropy("x" * 16, pool)
    check(abs(e - 16 * math.log2(pool)) < 1e-9, "entropy matches L*log2(pool)")

    check(pc.calculate_entropy("", 95) == 0, "empty password -> 0 entropy")
    check(pc.calculate_entropy("x" * 8, 1) == 0, "pool<2 -> 0 entropy")

    # Monotonicity in length
    e4 = pc.calculate_entropy("x" * 4, pool)
    e16 = pc.calculate_entropy("x" * 16, pool)
    e64 = pc.calculate_entropy("x" * 64, pool)
    check(e4 < e16 < e64, "entropy grows with length")

    # Monotonicity in pool
    e_small = pc.calculate_entropy("x" * 16, 10)
    e_large = pc.calculate_entropy("x" * 16, 100)
    check(e_small < e_large, "entropy grows with pool")

    # Crack-time buckets
    check(pc.estimate_crack_time(0) == "—", "0 bits -> dash")
    check(pc.estimate_crack_time(20) == "Instantly", "20 bits -> Instantly")
    check("second" in pc.estimate_crack_time(34), "34 bits -> seconds")
    check("minute" in pc.estimate_crack_time(40), "40 bits -> minutes")
    check("hour" in pc.estimate_crack_time(47), "47 bits -> hours")
    check("day" in pc.estimate_crack_time(55), "55 bits -> days")
    check("year" in pc.estimate_crack_time(62) and "thousand" not in pc.estimate_crack_time(62),
          "62 bits -> years (regular)")
    check("thousand years" in pc.estimate_crack_time(70), "70 bits -> thousand years")
    check("million years" in pc.estimate_crack_time(80), "80 bits -> million years")
    check("billion years" in pc.estimate_crack_time(90), "90 bits -> billion years")
    check(pc.estimate_crack_time(130) == "Centuries upon centuries",
          "130 bits -> Centuries upon centuries")


# ---------------------------------------------------------------------------
# Strength classifier
# ---------------------------------------------------------------------------
def verify_strength():
    section("calculate_strength buckets")

    check(pc.calculate_strength("") == "Weak", "empty -> Weak")
    check(pc.calculate_strength("a") == "Weak", "1 char -> Weak")
    check(pc.calculate_strength("abcdefgh") == "Weak", "8 lowercase -> Weak")
    check(pc.calculate_strength("Abcdef12") in ("Medium", "Strong"),
          "8 chars 3 categories -> Medium+")
    check(pc.calculate_strength("Abcdef12!@#$XyZ1") == "Very Strong",
          "16 chars 4 categories -> Very Strong")


# ---------------------------------------------------------------------------
# password_stats shape
# ---------------------------------------------------------------------------
def verify_stats_shape():
    section("password_stats round-trip")

    s = pc.password_stats("Abcdef12!@#$", pc.CHAR_SETS.keys())
    for key in (
        "length", "uppercase", "lowercase", "digits", "special",
        "unique_chars", "entropy_bits", "crack_time", "strength",
    ):
        check(key in s, f"stats has key {key!r}")
    check(s["length"] == len("Abcdef12!@#$"), "length matches")
    check(
        s["uppercase"] + s["lowercase"] + s["digits"] + s["special"] == s["length"],
        "category counts sum to length",
    )
    check(1 <= s["unique_chars"] <= s["length"], "unique_chars in range")
    check(s["strength"] in ("Weak", "Medium", "Strong", "Very Strong"),
          "strength is a known label")

    # Round-trip a generated password
    pwd = pc.generate_password(20, pc.CHAR_SETS.keys())
    s = pc.password_stats(pwd, pc.CHAR_SETS.keys())
    check(s["length"] == 20, "generated password stats length is 20")
    check(s["uppercase"] >= 1 and s["lowercase"] >= 1 and s["digits"] >= 1 and s["special"] >= 1,
          "every category represented in stats")


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------
def main() -> int:
    print("verify_core.py — password_core.py smoke test (no third-party deps)")
    try:
        verify_validate()
        verify_generation()
        verify_pool_size()
        verify_entropy_and_crack_time()
        verify_strength()
        verify_stats_shape()
    except AssertionError:
        print("\nFAILED")
        return 1
    except Exception:
        print("\nUNEXPECTED ERROR")
        traceback.print_exc()
        return 2
    print("\nAll smoke checks passed ✔")
    return 0


if __name__ == "__main__":
    sys.exit(main())
