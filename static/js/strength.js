// strength.js — entropy, crack-time, NIST score, and zxcvbn-lite feedback.

import { CHAR_SETS } from "./crypto.js";

/**
 * Returns the size of the union pool for the given categories.
 * Mirrors the helper in password_core.py.
 */
export function poolSize(categories, avoidAmbiguous = false) {
  const ambiguous = new Set("0OoIl1|`'\"{}[]()/\\.,:;<>");
  const set = new Set();
  for (const cat of categories) {
    if (!CHAR_SETS[cat]) continue;
    for (const ch of CHAR_SETS[cat]) {
      if (!avoidAmbiguous || !ambiguous.has(ch)) set.add(ch);
    }
  }
  return set.size;
}

/**
 * Shannon-style entropy in bits: H = L * log2(pool).
 */
export function calculateEntropy(password, pool) {
  if (!password || pool <= 1) return 0;
  return password.length * Math.log2(pool);
}

/**
 * Human-readable crack-time assuming 1e10 guesses/second (offline rig).
 */
export function estimateCrackTime(entropyBits) {
  if (entropyBits <= 0) return "—";
  const seconds = Math.pow(2, entropyBits) / 1e10;
  return formatDuration(seconds);
}

function formatDuration(s) {
  if (s < 1) return "Instantly";
  if (s < 60) return `${Math.round(s)} second${s >= 2 ? "s" : ""}`;
  if (s < 3600) return `${(s / 60).toFixed(1)} minutes`;
  if (s < 86400) return `${(s / 3600).toFixed(1)} hours`;
  if (s < 31536000) return `${(s / 86400).toFixed(1)} days`;
  if (s < 31536000 * 100) return `${(s / 31536000).toFixed(1)} years`;
  if (s < 31536000 * 1e6) return `${(s / 31536000 / 1e3).toFixed(1)} thousand years`;
  if (s < 31536000 * 1e9) return `${(s / 31536000 / 1e6).toFixed(1)} million years`;
  if (s < 31536000 * 1e12) return `${(s / 31536000 / 1e9).toFixed(1)} billion years`;
  return "Centuries upon centuries";
}

/**
 * 4-tier strength label matching the original Tkinter app.
 */
export function calculateStrength(password) {
  if (!password) return "Weak";
  let categories = 0;
  if (/[A-Z]/.test(password)) categories++;
  if (/[a-z]/.test(password)) categories++;
  if (/[0-9]/.test(password)) categories++;
  if (/[^A-Za-z0-9]/.test(password)) categories++;
  const L = password.length;
  const score = L * categories;
  if (L < 8 || categories < 2 || score < 16) return "Weak";
  if (L < 12 || score < 36) return "Medium";
  if (L < 16 || score < 64) return "Strong";
  return "Very Strong";
}

/**
 * NIST SP 800-63B-inspired 0..4 score:
 *   -1 char category present
 *   +length >= 8
 *   +length >= 12
 *   +length >= 15
 *   +no obvious pattern
 */
export function nistScore(password) {
  if (!password) return 0;
  let score = 0;
  if (/[A-Z]/.test(password)) score++;
  if (/[a-z]/.test(password)) score++;
  if (/[0-9]/.test(password)) score++;
  if (/[^A-Za-z0-9]/.test(password)) score++;
  if (password.length >= 8) score++;
  if (password.length >= 12) score++;
  if (password.length >= 15) score++;
  if (!hasObviousPattern(password)) score++;
  return Math.min(score, 8);
}

function hasObviousPattern(pwd) {
  if (/(.)\1{2,}/.test(pwd)) return true; // aaa, 111
  if (/(?:0123|1234|2345|3456|4567|5678|6789)/.test(pwd)) return true;
  if (/(?:abcd|bcde|cdef|defg|efgh|fghi|qwer|asdf|zxcv)/i.test(pwd)) return true;
  return false;
}

/**
 * Aggregate stats object.
 */
export function passwordStats(password, categories) {
  const pool = poolSize(categories);
  const entropy = calculateEntropy(password, pool);
  return {
    length: password.length,
    uppercase: (password.match(/[A-Z]/g) || []).length,
    lowercase: (password.match(/[a-z]/g) || []).length,
    digits: (password.match(/[0-9]/g) || []).length,
    special: (password.match(/[^A-Za-z0-9]/g) || []).length,
    uniqueChars: new Set(password).size,
    entropyBits: Math.round(entropy * 100) / 100,
    crackTime: estimateCrackTime(entropy),
    strength: calculateStrength(password),
  };
}

/* -------------------------- zxcvbn-lite -------------------------- */

const COMMON_LEET = [
  "p@ssw0rd", "passw0rd", "pa55word", "letmein", "qwerty",
  "admin", "welcome", "iloveyou", "monkey", "dragon",
  "football", "baseball", "sunshine", "princess", "trustno1",
];

const KEYBOARD_ROWS = [
  "qwertyuiop", "asdfghjkl", "zxcvbnm",
  "1234567890",
];

/**
 * Returns an array of feedback objects: {type, message}
 *   type: 'warn' | 'suggestion' | 'positive'
 */
export function analyzePassword(pwd) {
  const feedback = [];
  if (!pwd) {
    return [{ type: "warn", message: "Type a password to audit it." }];
  }

  // Length
  if (pwd.length < 8) {
    feedback.push({ type: "warn", message: "Too short — use at least 12 characters." });
  } else if (pwd.length < 12) {
    feedback.push({ type: "suggestion", message: "Consider 12+ characters for stronger security." });
  } else {
    feedback.push({ type: "positive", message: `Length: ${pwd.length} characters ✔` });
  }

  // Categories
  const cats = [
    [/[A-Z]/, "uppercase"],
    [/[a-z]/, "lowercase"],
    [/[0-9]/, "numbers"],
    [/[^A-Za-z0-9]/, "special"],
  ];
  const present = cats.filter(([re]) => re.test(pwd)).map(([, n]) => n);
  if (present.length < 3) {
    feedback.push({
      type: "suggestion",
      message: `Mix more character types — currently using ${present.length}/4.`,
    });
  } else {
    feedback.push({ type: "positive", message: `Uses ${present.length} character categories ✔` });
  }

  // Repetition
  if (/(.)\1{2,}/.test(pwd)) {
    feedback.push({ type: "warn", message: "Contains repeated characters (e.g. aaa)." });
  }

  // Sequences
  if (/(?:0123|1234|2345|3456|4567|5678|6789|abcd|bcde|cdef|qwer|asdf|zxcv)/i.test(pwd)) {
    feedback.push({ type: "warn", message: "Contains a sequential pattern (1234, qwerty, …)." });
  }

  // Keyboard rows
  for (const row of KEYBOARD_ROWS) {
    for (let i = 0; i + 4 <= row.length; i++) {
      const slice = row.slice(i, i + 4);
      if (pwd.toLowerCase().includes(slice)) {
        feedback.push({ type: "warn", message: `Contains keyboard pattern '${slice}'.` });
        break;
      }
    }
  }

  // Common leet
  const lower = pwd.toLowerCase();
  for (const common of COMMON_LEET) {
    if (lower.includes(common)) {
      feedback.push({ type: "warn", message: "Contains a common password fragment." });
      break;
    }
  }

  // Entropy verdict
  const ent = calculateEntropy(pwd, poolSize(["uppercase", "lowercase", "numbers", "special"]));
  if (ent >= 80) {
    feedback.push({ type: "positive", message: `High entropy (${ent.toFixed(0)} bits).` });
  } else if (ent < 40) {
    feedback.push({ type: "warn", message: `Low entropy (${ent.toFixed(0)} bits) — easy to crack.` });
  }

  return feedback;
}

/**
 * SHA-1 of a UTF-8 string, returned as uppercase hex.
 * Uses SubtleCrypto. Throws if unavailable (only true for very old browsers).
 */
export async function sha1Hex(str) {
  const data = new TextEncoder().encode(str);
  const buf = await crypto.subtle.digest("SHA-1", data);
  return [...new Uint8Array(buf)]
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("")
    .toUpperCase();
}
