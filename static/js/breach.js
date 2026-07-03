// breach.js — k-anonymity breach lookup against Have I Been Pwned.
//
// The full password is hashed locally with SHA-1 (via Web Crypto). Only the
// first 5 hex chars of the digest are sent to api.pwnedpasswords.com/range/{prefix};
// the response (a list of suffixes) is searched locally for the remaining
// 35 hex chars. The password itself never leaves the browser.
//
// Two safety rails:
//   - At most one /range request per RATE_LIMIT_MS milliseconds.
//   - Any in-flight request is aborted when a new one starts, or when the
//     caller explicitly calls abortBreach() (used by the input handler to
//     prevent stale results from a previous password).
//
// Public surface:
//   checkBreach(password)  -> { count, error? }
//   abortBreach()          -> void
//
//   count is the breach count (0 means "not found"). error is set only on
//   non-cancellation failures; for AbortError we return { count: 0,
//   error: "Cancelled" } and the UI is expected to drop the result on the
//   floor.

import { sha1Hex } from "./strength.js";

const HIBP_URL = "https://api.pwnedpasswords.com/range/";
const PREFIX_LEN = 5;
const RATE_LIMIT_MS = 250;

let inflight = null;     // AbortController of the currently-pending request
let lastFireAt = 0;      // ms timestamp of the last completed/failed fire

export function abortBreach() {
  if (inflight) {
    inflight.abort();
    inflight = null;
  }
}

export async function checkBreach(password) {
  if (typeof password !== "string" || password.length === 0) {
    return { count: 0, error: "Empty password" };
  }

  // Abort any in-flight request before starting a new one.
  abortBreach();
  const controller = new AbortController();
  inflight = controller;

  // Rate limit: wait out the remainder of the 250 ms window if needed.
  const wait = RATE_LIMIT_MS - (Date.now() - lastFireAt);
  if (wait > 0) {
    try {
      await new Promise((resolve, reject) => {
        const t = setTimeout(resolve, wait);
        controller.signal.addEventListener("abort", () => {
          clearTimeout(t);
          reject(new DOMException("Aborted", "AbortError"));
        }, { once: true });
      });
    } catch (e) {
      if (e && e.name === "AbortError") {
        return { count: 0, error: "Cancelled" };
      }
      throw e;
    }
    if (controller.signal.aborted) {
      return { count: 0, error: "Cancelled" };
    }
  }

  try {
    const hash = await sha1Hex(password);
    const prefix = hash.slice(0, PREFIX_LEN);
    const suffix = hash.slice(PREFIX_LEN);

    const res = await fetch(HIBP_URL + prefix, {
      signal: controller.signal,
      headers: { "Add-Padding": "true" },
    });
    if (!res.ok) {
      return { count: 0, error: `HIBP ${res.status}` };
    }

    const text = await res.text();
    for (const line of text.split(/\r?\n/)) {
      if (!line) continue;
      const [s, c] = line.split(":");
      if (s && s.toUpperCase() === suffix) {
        const n = parseInt(c, 10);
        return { count: Number.isFinite(n) ? n : 0 };
      }
    }
    return { count: 0 };
  } catch (e) {
    if (e && e.name === "AbortError") {
      return { count: 0, error: "Cancelled" };
    }
    return { count: 0, error: (e && e.message) || "Network error" };
  } finally {
    lastFireAt = Date.now();
    if (inflight === controller) inflight = null;
  }
}
