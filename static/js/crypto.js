// crypto.js — cryptographically secure password generation in the browser.
// Uses the Web Crypto API (crypto.getRandomValues) so the random source
// matches the strength of the Python `secrets` module.

const CHAR_SETS = {
  uppercase: "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
  lowercase: "abcdefghijklmnopqrstuvwxyz",
  numbers: "0123456789",
  special: "!@#$%^&*()-_=+[]{};:,.<>/?~",
};

const AMBIGUOUS_CHARS = new Set("0OoIl1|`'\"{}[]()/\\.,:;<>");

/**
 * Read `count` uniformly distributed integers in [0, max) using rejection
 * sampling to remove modulo bias. Returns a Uint32Array.
 */
function uniformInts(count, max) {
  if (max <= 0) throw new Error("max must be > 0");
  // Rejection threshold = largest multiple of max that fits in 2^32
  const limit = Math.floor(0x100000000 / max) * max;
  const out = new Uint32Array(count);
  let filled = 0;
  const buf = new Uint32Array(count * 2);
  while (filled < count) {
    crypto.getRandomValues(buf);
    for (let i = 0; i < buf.length && filled < count; i++) {
      if (buf[i] < limit) {
        out[filled++] = buf[i] % max;
      }
    }
  }
  return out;
}

/**
 * Fisher–Yates shuffle backed by crypto.getRandomValues.
 */
function secureShuffle(arr) {
  const a = arr.slice();
  for (let i = a.length - 1; i > 0; i--) {
    const j = uniformInts(1, i + 1)[0];
    [a[i], a[j]] = [a[j], a[i]];
  }
  return a;
}

function poolFor(categories, avoidAmbiguous) {
  let pool = categories.map((c) => CHAR_SETS[c] || "").join("");
  if (avoidAmbiguous) {
    pool = [...pool].filter((ch) => !AMBIGUOUS_CHARS.has(ch)).join("");
  }
  return pool;
}

/**
 * Generate a single password.
 *
 *   length:           integer 4..128
 *   categories:       array of keys in CHAR_SETS
 *   avoidAmbiguous:   boolean, drops 0/O o/I l/1 etc. from the pool
 *
 * Guarantees that every selected category appears at least once.
 */
export function generatePasswordClient(length, categories, avoidAmbiguous = false) {
  if (!Array.isArray(categories) || categories.length === 0) {
    throw new Error("At least one category is required.");
  }
  if (!Number.isInteger(length) || length < 4 || length > 128) {
    throw new Error("Length must be an integer in [4, 128].");
  }
  if (length < categories.length) {
    throw new Error("Length is too short for the number of selected categories.");
  }

  const pool = poolFor(categories, avoidAmbiguous);
  if (!pool) {
    throw new Error("Selected categories produced an empty pool.");
  }

  // 1. Seed one character from each category (filtered for ambiguous if needed).
  const seeded = [];
  for (const cat of categories) {
    let catPool = CHAR_SETS[cat] || "";
    if (avoidAmbiguous) {
      catPool = [...catPool].filter((ch) => !AMBIGUOUS_CHARS.has(ch)).join("");
    }
    if (catPool) {
      const idx = uniformInts(1, catPool.length)[0];
      seeded.push(catPool[idx]);
    }
  }
  // 2. Fill the rest from the union pool.
  const remaining = length - seeded.length;
  const indices = uniformInts(remaining, pool.length);
  for (let i = 0; i < remaining; i++) {
    seeded.push(pool[indices[i]]);
  }
  // 3. Shuffle.
  return secureShuffle(seeded).join("");
}

export function generateBatch(length, count, categories, avoidAmbiguous = false) {
  return Array.from({ length: count }, () =>
    generatePasswordClient(length, categories, avoidAmbiguous)
  );
}

export { CHAR_SETS, AMBIGUOUS_CHARS };
