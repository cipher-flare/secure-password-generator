"""
Unit tests for password_core.py.

Covers:
- Validation boundaries (length, count, categories, types)
- Category guarantee across all (length × category) combinations
- pool_size with and without avoid_ambiguous
- Entropy monotonicity in length and monotonicity in pool size
- estimate_crack_time formatter (buckets)
- calculate_strength classifier buckets
- Round-trip shape of password_stats

Run with: pytest -q
"""

from __future__ import annotations

import math

import pytest

from password_core import (
    AMBIGUOUS_CHARS,
    CHAR_SETS,
    MAX_COUNT,
    MAX_LENGTH,
    MIN_COUNT,
    MIN_LENGTH,
    calculate_entropy,
    calculate_strength,
    estimate_crack_time,
    generate_password,
    password_stats,
    pool_size,
    validate_inputs,
)

ALL_CATS = ["uppercase", "lowercase", "numbers", "special"]


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------
class TestValidateInputs:
    def test_valid_minimums(self):
        ok, length, count, err = validate_inputs(MIN_LENGTH, MIN_COUNT, ["lowercase"])
        assert ok is True
        assert err == ""
        assert length == MIN_LENGTH
        assert count == MIN_COUNT

    def test_valid_maximums(self):
        ok, length, count, err = validate_inputs(MAX_LENGTH, MAX_COUNT, ALL_CATS)
        assert ok is True
        assert length == MAX_LENGTH
        assert count == MAX_COUNT

    def test_coerces_string_ints(self):
        ok, length, count, err = validate_inputs("20", "3", ["lowercase"])
        assert ok is True
        assert length == 20
        assert count == 3

    def test_length_below_min(self):
        ok, length, count, err = validate_inputs(MIN_LENGTH - 1, 1, ["lowercase"])
        assert ok is False
        assert length == 0
        assert count == 0
        assert "at least" in err

    def test_length_above_max(self):
        ok, length, count, err = validate_inputs(MAX_LENGTH + 1, 1, ["lowercase"])
        assert ok is False
        assert "exceed" in err

    def test_count_below_min(self):
        ok, length, count, err = validate_inputs(16, MIN_COUNT - 1, ["lowercase"])
        assert ok is False
        assert "at least" in err

    def test_count_above_max(self):
        ok, length, count, err = validate_inputs(16, MAX_COUNT + 1, ["lowercase"])
        assert ok is False
        assert "exceed" in err

    def test_length_non_integer(self):
        ok, length, count, err = validate_inputs("abc", 1, ["lowercase"])
        assert ok is False
        assert "whole number" in err

    def test_length_rejects_bool(self):
        ok, length, count, err = validate_inputs(True, 1, ["lowercase"])
        assert ok is False
        assert "whole number" in err

    def test_length_rejects_empty_string(self):
        ok, length, count, err = validate_inputs("   ", 1, ["lowercase"])
        assert ok is False
        assert "required" in err

    def test_count_rejects_non_integer(self):
        ok, length, count, err = validate_inputs(16, [], ["lowercase"])
        assert ok is False

    def test_no_categories(self):
        ok, length, count, err = validate_inputs(16, 1, [])
        assert ok is False
        assert "category" in err

    def test_unknown_category_filtered_then_empty(self):
        # Unknown category names are silently dropped; if nothing real remains,
        # validation fails.
        ok, length, count, err = validate_inputs(16, 1, ["not_a_category"])
        assert ok is False
        assert "category" in err

    def test_mixed_known_and_unknown_categories(self):
        ok, length, count, err = validate_inputs(16, 1, ["uppercase", "fake"])
        assert ok is True


# ---------------------------------------------------------------------------
# Category guarantee
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "categories",
    [
        ["uppercase"],
        ["lowercase"],
        ["numbers"],
        ["special"],
        ["uppercase", "lowercase"],
        ["uppercase", "numbers"],
        ["uppercase", "special"],
        ["lowercase", "numbers"],
        ["lowercase", "special"],
        ["numbers", "special"],
        ["uppercase", "lowercase", "numbers"],
        ["uppercase", "lowercase", "special"],
        ["uppercase", "numbers", "special"],
        ["lowercase", "numbers", "special"],
        ["uppercase", "lowercase", "numbers", "special"],
    ],
)
@pytest.mark.parametrize("length", [4, 8, 16, 32, 64])
def test_every_selected_category_appears(categories, length):
    # Skip combos where the length is shorter than the number of categories
    # (the generator itself raises on those; the contract is that it's enforced).
    if length < len(categories):
        with pytest.raises(ValueError):
            generate_password(length, categories)
        return
    pwd = generate_password(length, categories)
    assert len(pwd) == length
    for cat in categories:
        pool = CHAR_SETS[cat]
        assert any(ch in pool for ch in pwd), (
            f"Category {cat!r} not represented in {pwd!r}"
        )


def test_length_below_categories_raises():
    with pytest.raises(ValueError):
        generate_password(2, ["uppercase", "lowercase", "numbers", "special"])


def test_no_categories_raises():
    with pytest.raises(ValueError):
        generate_password(16, [])


def test_avoid_ambiguous_filters_ambiguous_chars():
    pwd = generate_password(64, ALL_CATS, avoid_ambiguous=True)
    for ch in pwd:
        assert ch not in AMBIGUOUS_CHARS


def test_strict_mode_still_includes_all_categories():
    # The strict mode must not break the category guarantee.
    pwd = generate_password(32, ALL_CATS, avoid_ambiguous=True, strict=True)
    assert len(pwd) == 32
    for cat in ALL_CATS:
        pool = CHAR_SETS[cat]
        # When avoid_ambiguous is on, the per-category pool may be empty
        # (e.g. special drops many chars but is never empty in practice);
        # we only check that the category's characters are present in
        # the original CHAR_SETS.
        assert any(ch in pool for ch in pwd), (
            f"Category {cat!r} missing under strict mode from {pwd!r}"
        )


def test_strict_only_engages_with_four_categories_and_length_16_plus():
    # When fewer than four categories are selected, strict must not change behavior.
    pwd1 = generate_password(20, ["lowercase", "numbers"])
    pwd2 = generate_password(20, ["lowercase", "numbers"], strict=True)
    assert len(pwd1) == 20
    assert len(pwd2) == 20
    for ch in pwd1:
        assert ch in CHAR_SETS["lowercase"] + CHAR_SETS["numbers"]
    for ch in pwd2:
        assert ch in CHAR_SETS["lowercase"] + CHAR_SETS["numbers"]


def test_avoid_ambiguous_does_not_crash_on_empty_per_category_pool():
    # If a category's pool becomes empty after removing ambiguous chars, the
    # generator must fall back to the union pool rather than raising.
    # (This is a regression guard, not a hit-by-design case for ASCII punctuation.)
    pwd = generate_password(16, ["numbers"], avoid_ambiguous=True)
    assert len(pwd) == 16
    for ch in pwd:
        assert ch in "0123456789"  # '0' and '1' are ambiguous but still in pool
        # The point of the test is no crash, but we additionally check we got digits.


# ---------------------------------------------------------------------------
# pool_size
# ---------------------------------------------------------------------------
class TestPoolSize:
    def test_all_categories(self):
        assert pool_size(ALL_CATS) == sum(len(s) for s in CHAR_SETS.values())

    def test_single_category(self):
        assert pool_size(["lowercase"]) == 26

    def test_avoid_ambiguous_removes_chars(self):
        full = pool_size(["numbers"])
        filtered = pool_size(["numbers"], avoid_ambiguous=True)
        # '0' and '1' are ambiguous → filtered pool loses 2 chars
        assert filtered == full - 2

    def test_unknown_categories_ignored(self):
        assert pool_size(["not_a_category", "lowercase"]) == 26

    def test_empty(self):
        assert pool_size([]) == 0


# ---------------------------------------------------------------------------
# Entropy monotonicity
# ---------------------------------------------------------------------------
class TestEntropyMonotonicity:
    def test_longer_password_higher_entropy(self):
        pool = pool_size(ALL_CATS)
        e4 = calculate_entropy("x" * 4, pool)
        e16 = calculate_entropy("x" * 16, pool)
        e64 = calculate_entropy("x" * 64, pool)
        assert e4 < e16 < e64

    def test_larger_pool_higher_entropy(self):
        e_small = calculate_entropy("x" * 16, 10)
        e_large = calculate_entropy("x" * 16, 100)
        assert e_small < e_large

    def test_formula_is_length_times_log2_pool(self):
        for length in [8, 16, 32]:
            for pool in [26, 62, 94]:
                expected = length * math.log2(pool)
                assert calculate_entropy("x" * length, pool) == pytest.approx(expected)

    def test_empty_password_returns_zero(self):
        assert calculate_entropy("", 95) == 0.0

    def test_pool_below_two_returns_zero(self):
        assert calculate_entropy("x" * 8, 1) == 0.0


# ---------------------------------------------------------------------------
# Crack-time formatter
# ---------------------------------------------------------------------------
class TestCrackTimeBuckets:
    def test_zero_or_negative_returns_dash(self):
        assert estimate_crack_time(0) == "—"
        assert estimate_crack_time(-5) == "—"

    def test_instantly_bucket(self):
        # entropy < log2(1e10) ≈ 33.2 → "Instantly"
        assert estimate_crack_time(20) == "Instantly"

    def test_seconds_bucket(self):
        # ~33.2 bits → a few seconds
        s = estimate_crack_time(34)
        assert "second" in s

    def test_minutes_bucket(self):
        # 2^40 / 1e10 ≈ 109 seconds → falls in "minutes" bucket (< 3600 s)
        s = estimate_crack_time(40)
        assert "minute" in s

    def test_hours_bucket(self):
        # 2^47 / 1e10 ≈ 14,400 s ≈ 4 h
        s = estimate_crack_time(47)
        assert "hour" in s

    def test_days_bucket(self):
        # 2^55 / 1e10 ≈ 3.6e6 s ≈ 41 days
        s = estimate_crack_time(55)
        assert "day" in s

    def test_years_bucket(self):
        # 2^62 / 1e10 ≈ 4.6e8 s ≈ 14.6 years
        s = estimate_crack_time(62)
        assert "year" in s
        assert "thousand" not in s
        assert "million" not in s

    def test_thousand_years_bucket(self):
        # 2^70 / 1e10 ≈ 1.18e11 s → ~3,750 years → "thousand years"
        s = estimate_crack_time(70)
        assert "thousand years" in s

    def test_million_years_bucket(self):
        # 2^80 / 1e10 ≈ 1.21e14 s → ~3.8M years → "million years"
        s = estimate_crack_time(80)
        assert "million years" in s

    def test_billion_years_bucket(self):
        # 2^90 / 1e10 ≈ 1.24e17 s → ~3.9B years → "billion years"
        s = estimate_crack_time(90)
        assert "billion years" in s

    def test_centuries_upon_centuries_bucket(self):
        # 2^130 / 1e10 ≈ 1.36e29 s → Centuries upon centuries
        s = estimate_crack_time(130)
        assert s == "Centuries upon centuries"


# ---------------------------------------------------------------------------
# Strength classifier
# ---------------------------------------------------------------------------
class TestStrengthBuckets:
    def test_empty_is_weak(self):
        assert calculate_strength("") == "Weak"

    def test_short_single_category_is_weak(self):
        assert calculate_strength("abc") == "Weak"
        assert calculate_strength("ABC") == "Weak"

    def test_eight_chars_two_categories_medium_or_better(self):
        # 8 chars * 2 cats = 16 → Weak floor
        assert calculate_strength("abcdefgh") == "Weak"  # only lowercase
        # 8 chars * 3 cats = 24 → at least Medium
        assert calculate_strength("Abcdef12") in ("Medium", "Strong")

    def test_twelve_chars_four_categories_strong_or_better(self):
        # 12 * 4 = 48 → Strong
        result = calculate_strength("Abcdef12!@#$")
        assert result in ("Strong", "Very Strong")

    def test_sixteen_chars_four_categories_very_strong(self):
        # 16 * 4 = 64 → Very Strong
        result = calculate_strength("Abcdef12!@#$XyZ1")
        assert result == "Very Strong"

    def test_classifier_is_monotonic(self):
        # Strengthening the input (longer, more categories) must not lower the bucket.
        weak = calculate_strength("a")
        medium = calculate_strength("Ab1")
        strong = calculate_strength("Abcdef12")
        very_strong = calculate_strength("Abcdef12!@#$XyZ1")
        order = {"Weak": 0, "Medium": 1, "Strong": 2, "Very Strong": 3}
        assert order[weak] <= order[medium] <= order[strong] <= order[very_strong]


# ---------------------------------------------------------------------------
# password_stats shape
# ---------------------------------------------------------------------------
class TestPasswordStatsShape:
    def test_required_keys_present(self):
        s = password_stats("Abcdef12!@#$", ALL_CATS)
        for key in (
            "length",
            "uppercase",
            "lowercase",
            "digits",
            "special",
            "unique_chars",
            "entropy_bits",
            "crack_time",
            "strength",
        ):
            assert key in s, f"Missing key: {key}"

    def test_counts_add_up_to_length(self):
        s = password_stats("Abcdef12!@#$", ALL_CATS)
        assert s["length"] == len("Abcdef12!@#$")
        assert s["uppercase"] + s["lowercase"] + s["digits"] + s["special"] == s["length"]

    def test_unique_chars_le_length(self):
        s = password_stats("Abcdef12!@#$", ALL_CATS)
        assert 1 <= s["unique_chars"] <= s["length"]

    def test_entropy_bits_is_rounded(self):
        s = password_stats("Abcdef12!@#$", ALL_CATS)
        # round(x, 2) → at most 2 decimal places
        assert s["entropy_bits"] == round(s["entropy_bits"], 2)

    def test_crack_time_is_human_string(self):
        s = password_stats("Abcdef12!@#$", ALL_CATS)
        assert isinstance(s["crack_time"], str)
        assert s["crack_time"]  # non-empty

    def test_strength_is_known_label(self):
        s = password_stats("Abcdef12!@#$", ALL_CATS)
        assert s["strength"] in ("Weak", "Medium", "Strong", "Very Strong")

    def test_round_trip_on_generated_password(self):
        pwd = generate_password(20, ALL_CATS)
        s = password_stats(pwd, ALL_CATS)
        assert s["length"] == 20
        # The generator guarantees every category is present.
        assert s["uppercase"] >= 1
        assert s["lowercase"] >= 1
        assert s["digits"] >= 1
        assert s["special"] >= 1
