"""
password_core.py
================
Pure password generation, validation, and analysis logic.

This module has zero dependencies on Flask, the web layer, or any I/O so it
can be unit-tested in isolation and reused from both the HTTP routes and any
future CLI / desktop front end.

Public API
----------
    CHAR_SETS            - dict mapping category name to character set
    AMBIGUOUS_CHARS      - characters that look alike (0/O, 1/l/I, etc.)
    MIN_LENGTH, MAX_LENGTH, MAX_COUNT
    generate_password(length, categories, *, avoid_ambiguous=False) -> str
    validate_inputs(length, count, categories) ->
        (ok, length, count, error_message)
    calculate_strength(password) -> str   # Weak / Medium / Strong / Very Strong
    pool_size(categories, avoid_ambiguous=False) -> int
    calculate_entropy(password, pool_size) -> float   # bits
    estimate_crack_time(entropy_bits) -> str           # human readable
    password_stats(password, categories) -> dict
"""

from __future__ import annotations

import math
import re
import secrets
import string
from typing import Iterable

# ---------------------------------------------------------------------------
# Character sets
# ---------------------------------------------------------------------------
CHAR_SETS: dict[str, str] = {
    "uppercase": string.ascii_uppercase,
    "lowercase": string.ascii_lowercase,
    "numbers": string.digits,
    "special": string.punctuation,
}

# Characters that look alike and are easy to misread on paper or screen.
AMBIGUOUS_CHARS = set("0OoIl1|`'\"{}[]()/\\.,:;<>")

# Limits
MIN_LENGTH = 4
MAX_LENGTH = 128
MIN_COUNT = 1
MAX_COUNT = 50


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------
def _coerce_int(name: str, value, minimum: int, maximum: int) -> tuple[bool, int | None, str]:
    """Return (ok, value, error_message) for an integer field."""
    if value is None or (isinstance(value, str) and not value.strip()):
        return False, None, f"{name} is required."
    if isinstance(value, bool):
        return False, None, f"{name} must be a whole number."
    if isinstance(value, str):
        s = value.strip()
        if not s.isdigit():
            return False, None, f"{name} must be a whole number."
        value = int(s)
    elif not isinstance(value, int):
        return False, None, f"{name} must be a whole number."
    if value < minimum:
        return False, None, f"{name} must be at least {minimum}."
    if value > maximum:
        return False, None, f"{name} cannot exceed {maximum}."
    return True, value, ""


def validate_inputs(
    length, count, categories: Iterable[str]
) -> tuple[bool, int, int, str]:
    """
    Validate user inputs. Returns (ok, length, count, error_message).

    On success, ``length`` and ``count`` are the coerced integer values that
    the caller should use directly (no need to ``int(...)`` them again).
    On failure, the int fields are set to ``0`` and ``error_message``
    explains what was wrong.

    Rules
    -----
    - length must be an integer in [MIN_LENGTH, MAX_LENGTH]
    - count  must be an integer in [MIN_COUNT, MAX_COUNT]
    - categories must contain at least one known category
    """
    ok, length, err = _coerce_int("Password length", length, MIN_LENGTH, MAX_LENGTH)
    if not ok:
        return False, 0, 0, err

    ok, count, err = _coerce_int("Number of passwords", count, MIN_COUNT, MAX_COUNT)
    if not ok:
        return False, 0, 0, err

    selected = [c for c in (categories or []) if c in CHAR_SETS]
    if not selected:
        return False, 0, 0, "Select at least one character category."

    return True, length, count, ""


# ---------------------------------------------------------------------------
# Generation
# ---------------------------------------------------------------------------
def pool_size(categories: Iterable[str], avoid_ambiguous: bool = False) -> int:
    """Total characters available across the selected categories."""
    pool = "".join(CHAR_SETS[c] for c in categories if c in CHAR_SETS)
    if avoid_ambiguous:
        pool = "".join(ch for ch in pool if ch not in AMBIGUOUS_CHARS)
    return len(pool)


def generate_password(
    length: int,
    categories: Iterable[str],
    *,
    avoid_ambiguous: bool = False,
    strict: bool = False,
) -> str:
    """
    Generate a single cryptographically secure password.

    Algorithm
    ---------
    1. Seed one mandatory character from each selected category.
    2. Fill the remaining slots from the union pool using ``secrets.choice``.
    3. Shuffle with ``secrets.SystemRandom`` so the seeded characters are
       randomly positioned.

    With ``strict=True``, when all four character categories are selected
    and ``length >= 16``, any seeded character that would duplicate a
    previously seeded character is re-drawn from the union pool instead
    of its category. This guards against the pathological case where
    filtering (e.g. ``avoid_ambiguous``) shrinks the per-category seed
    pool to a single character and the seeded characters happen to
    collide, leaving the rest of the password effectively random over a
    smaller-than-expected union.
    """
    selected = [c for c in categories if c in CHAR_SETS]
    if not selected:
        raise ValueError("At least one character category is required.")
    if length < len(selected):
        raise ValueError(
            f"Length {length} is too short to include all {len(selected)} selected categories."
        )

    full_pool = "".join(CHAR_SETS[c] for c in selected)
    if avoid_ambiguous:
        full_pool = "".join(ch for ch in full_pool if ch not in AMBIGUOUS_CHARS)
    if not full_pool:
        raise ValueError("Selected categories are empty after removing ambiguous characters.")

    # Seed one mandatory character from each category (also dedup-able for
    # the case where two categories share no unique characters after filtering).
    seeded: list[str] = []
    for cat in selected:
        cat_pool = "".join(
            ch for ch in CHAR_SETS[cat] if ch not in (AMBIGUOUS_CHARS if avoid_ambiguous else set())
        )
        if cat_pool:
            ch = secrets.choice(cat_pool)
            # Strict mode: if this seed would duplicate an earlier one, draw
            # from the union pool instead so the category is still represented
            # but the seed is genuinely distinct.
            if strict and len(selected) == 4 and length >= 16 and ch in seeded:
                if full_pool:
                    ch = secrets.choice(full_pool)
            seeded.append(ch)

    # If filtering removed every char in a category, fall back to the union pool
    # for the remaining mandatory slots so we never crash.
    rng = secrets.SystemRandom()
    while len(seeded) < min(length, len(selected)):
        seeded.append(secrets.choice(full_pool))

    remaining = length - len(seeded)
    seeded.extend(secrets.choice(full_pool) for _ in range(remaining))
    rng.shuffle(seeded)
    return "".join(seeded)


# ---------------------------------------------------------------------------
# Strength & entropy
# ---------------------------------------------------------------------------
def calculate_strength(password: str) -> str:
    """
    Classify a password as Weak / Medium / Strong / Very Strong.

    Heuristic combines length with the diversity of character categories
    present in the password.
    """
    if not password:
        return "Weak"

    categories = 0
    if re.search(r"[A-Z]", password):
        categories += 1
    if re.search(r"[a-z]", password):
        categories += 1
    if re.search(r"[0-9]", password):
        categories += 1
    if re.search(r"[^A-Za-z0-9]", password):
        categories += 1

    length = len(password)
    score = length * categories

    if length < 8 or categories < 2 or score < 16:
        return "Weak"
    if length < 12 or score < 36:
        return "Medium"
    if length < 16 or score < 64:
        return "Strong"
    return "Very Strong"


def calculate_entropy(password: str, pool: int) -> float:
    """
    Shannon-style entropy in bits, assuming uniform random selection from
    a pool of size ``pool``:  H = L * log2(pool).

    Returns 0.0 for empty input.
    """
    if not password or pool <= 1:
        return 0.0
    return len(password) * math.log2(pool)


def estimate_crack_time(entropy_bits: float) -> str:
    """
    Human-readable crack-time estimate assuming an offline rig capable of
    10 billion (1e10) guesses per second.
    """
    if entropy_bits <= 0:
        return "—"
    guesses = 2 ** entropy_bits
    seconds = guesses / 1e10
    return _format_duration(seconds)


def _format_duration(seconds: float) -> str:
    if seconds < 1:
        return "Instantly"
    if seconds < 60:
        return f"{int(seconds)} second{'s' if seconds >= 2 else ''}"
    if seconds < 3600:
        m = seconds / 60
        return f"{m:.1f} minutes"
    if seconds < 86_400:
        h = seconds / 3600
        return f"{h:.1f} hours"
    if seconds < 31_536_000:
        d = seconds / 86_400
        return f"{d:.1f} days"
    if seconds < 31_536_000 * 100:
        y = seconds / 31_536_000
        return f"{y:.1f} years"
    if seconds < 31_536_000 * 1_000_000:
        ky = seconds / 31_536_000 / 1_000
        return f"{ky:.1f} thousand years"
    if seconds < 31_536_000 * 1_000_000_000:
        my = seconds / 31_536_000 / 1_000_000
        return f"{my:.1f} million years"
    if seconds < 31_536_000 * 1_000_000_000_000:
        by = seconds / 31_536_000 / 1_000_000_000
        return f"{by:.1f} billion years"
    return "Centuries upon centuries"


# ---------------------------------------------------------------------------
# Aggregate stats
# ---------------------------------------------------------------------------
def password_stats(password: str, categories: Iterable[str]) -> dict:
    """Return a dictionary of statistics for the given password."""
    pool = pool_size(categories)
    entropy = calculate_entropy(password, pool)
    return {
        "length": len(password),
        "uppercase": sum(1 for ch in password if ch.isupper()),
        "lowercase": sum(1 for ch in password if ch.islower()),
        "digits": sum(1 for ch in password if ch.isdigit()),
        "special": sum(1 for ch in password if not ch.isalnum()),
        "unique_chars": len(set(password)),
        "entropy_bits": round(entropy, 2),
        "crack_time": estimate_crack_time(entropy),
        "strength": calculate_strength(password),
    }
