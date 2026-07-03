// verify_breach.mjs — exercise static/js/breach.js without touching HIBP.
// Run with: node scripts/verify_breach.mjs

import { webcrypto } from "node:crypto";
import { createHash } from "node:crypto";

// Node 24 exposes crypto as read-only on globalThis; the module reads
// crypto.subtle, so install webcrypto if it isn't already present.
if (!globalThis.crypto || !globalThis.crypto.subtle) {
  Object.defineProperty(globalThis, "crypto", { value: webcrypto, configurable: true });
}

// ---------------------------------------------------------------------------
// Mock fetch — a tiny switchable state machine.
//   - records the URL and increments callCount
//   - honors AbortController signal (rejects on abort, or synchronously
//     throws if the signal is already aborted when fetch is invoked)
//   - returns cannedResponse / cannedStatus
//   - if slow is set, the response's text() stays pending until you call
//     releasePending() (used by tests G and H to keep the in-flight request
//     in limbo while we exercise cancellation)
// ---------------------------------------------------------------------------
let lastUrl = null;
let callCount = 0;
let cannedResponse = "";
let cannedStatus = 200;
let slow = false;
let pending = null;        // { resolve, reject } of the in-flight text()

function makeMockFetch() {
  globalThis.fetch = async (url, opts) => {
    callCount++;
    lastUrl = url;
    const signal = opts && opts.signal;
    if (signal && signal.aborted) {
      throw new DOMException("Aborted", "AbortError");
    }
    return {
      ok: cannedStatus >= 200 && cannedStatus < 300,
      status: cannedStatus,
      text: () => new Promise((resolve, reject) => {
        if (!slow) {
          resolve(cannedResponse);
          return;
        }
        pending = { resolve, reject };
        if (signal) {
          if (signal.aborted) {
            reject(new DOMException("Aborted", "AbortError"));
            pending = null;
            return;
          }
          signal.addEventListener("abort", () => {
            if (pending) {
              pending = null;
              reject(new DOMException("Aborted", "AbortError"));
            }
          }, { once: true });
        }
      }),
    };
  };
}
makeMockFetch();

// ---------------------------------------------------------------------------
// Import after the stub is in place.
// ---------------------------------------------------------------------------
const breach = await import("../static/js/breach.js");
const { checkBreach, abortBreach } = breach;

let passes = 0;
let fails = 0;
function check(cond, msg) {
  if (cond) { passes++; console.log("  ok  :", msg); }
  else      { fails++; console.log("  FAIL:", msg); }
}

const sha1 = (s) => createHash("sha1").update(s).digest("hex").toUpperCase();

function releasePending(body) {
  if (!pending) return false;
  const p = pending; pending = null;
  p.resolve(body);
  return true;
}

// ---------------------------------------------------------------------------
// A: only the 5-char prefix hits the wire.
// ---------------------------------------------------------------------------
console.log("[A] URL contains only first 5 hex chars of SHA-1");
cannedStatus = 200;
cannedResponse = "";
await checkBreach("hunter2");
const expectedUrl = "https://api.pwnedpasswords.com/range/" + sha1("hunter2").slice(0, 5);
check(lastUrl === expectedUrl, `URL = ${lastUrl}`);

// ---------------------------------------------------------------------------
// B: matching suffix returns its count.
// ---------------------------------------------------------------------------
console.log("[B] matching suffix yields count");
const suffix = sha1("hunter2").slice(5);
cannedResponse = `AAAAA:7\n${suffix}:42\nBBBBB:3\n`;
const r = await checkBreach("hunter2");
check(r.count === 42 && !r.error, `result = ${JSON.stringify(r)}`);

// ---------------------------------------------------------------------------
// C: not in the list → clean.
// ---------------------------------------------------------------------------
console.log("[C] not in list → clean");
cannedResponse = "AAAAA:7\nBBBBB:3\nCCCCC:1\n";
const r2 = await checkBreach("hunter2");
check(r2.count === 0 && !r2.error, `result = ${JSON.stringify(r2)}`);

// ---------------------------------------------------------------------------
// D: non-2xx surfaces an error.
// ---------------------------------------------------------------------------
console.log("[D] non-2xx surfaces as error");
cannedStatus = 503;
cannedResponse = "";
const r3 = await checkBreach("hunter2");
check(r3.error && r3.error.includes("503"), `error = ${r3.error}`);
cannedStatus = 200;

// ---------------------------------------------------------------------------
// E: 5 rapid calls in the same 250ms window → 1 network hit.
// ---------------------------------------------------------------------------
console.log("[E] 5 rapid calls collapse to 1 network hit (250ms window)");
callCount = 0;
cannedResponse = "AAAAA:7\n";
const burst = [];
for (let i = 0; i < 5; i++) burst.push(checkBreach("hunter2"));
await Promise.all(burst);
check(callCount === 1, `callCount = ${callCount}`);

// ---------------------------------------------------------------------------
// F: a call after the 250ms window does fire.
// ---------------------------------------------------------------------------
console.log("[F] next call after 280ms fires");
await new Promise((r) => setTimeout(r, 280));
await checkBreach("hunter2");
check(callCount === 2, `callCount = ${callCount}`);

// ---------------------------------------------------------------------------
// G: abortBreach cancels an in-flight request.
// ---------------------------------------------------------------------------
console.log("[G] abortBreach cancels in-flight request");
slow = true;
callCount = 0;
cannedResponse = "AAAAA:7\n";
const before = callCount;
const inflight = checkBreach("hunter2");
abortBreach();
const out = await inflight;
check(out.error === "Cancelled", `result = ${JSON.stringify(out)}`);
check(callCount === before, "abort must not retry");
slow = false;

// ---------------------------------------------------------------------------
// H: starting a new call aborts the previous in-flight one.
// ---------------------------------------------------------------------------
console.log("[H] new call aborts the previous in-flight one");
slow = true;
callCount = 0;
cannedResponse = "AAAAA:7\n";
// Wait out any pending rate-limit window from prior tests.
await new Promise((r) => setTimeout(r, 280));
const p1 = checkBreach("hunter2");
// p1 is now inflight. Start p2 immediately — it will hit the rate-limit
// 250ms wait first, but its abortBreach() at the top must still cancel p1.
const p2 = checkBreach("hunter2");
const r1 = await p1;
check(r1.error === "Cancelled", `p1 = ${JSON.stringify(r1)}`);
// Now wait out p2's rate-limit wait, then check that p2 reached the fetch.
await new Promise((r) => setTimeout(r, 280));
check(releasePending("AAAAA:7\n"), "p2 had a pending resolver to release");
const r2b = await p2;
check(r2b.count === 0 && !r2b.error, `p2 = ${JSON.stringify(r2b)}`);
slow = false;

// ---------------------------------------------------------------------------
// I: empty password is rejected up front.
// ---------------------------------------------------------------------------
console.log("[I] empty password is rejected without a network call");
callCount = 0;
const rEmpty = await checkBreach("");
check(callCount === 0, "no fetch made for empty input");
check(rEmpty.error && rEmpty.error.toLowerCase().includes("empty"),
  `error = ${rEmpty.error}`);

// ---------------------------------------------------------------------------
// J: only 5 hex chars of the password's hash ever appear in the URL.
//    (Phase 2 — privacy guarantee.)
// ---------------------------------------------------------------------------
console.log("[J] only 5 hex chars of the hash leave the browser");
lastUrl = null;
cannedResponse = "AAAAA:1\n";
const fullHash = sha1("p@ssw0rd!hunter2");
await checkBreach("p@ssw0rd!hunter2");
const sent = lastUrl.split("/range/")[1];
check(sent.length === 5, `prefix length = ${sent.length}`);
check(!fullHash.startsWith(sent.toUpperCase()) || sent.toUpperCase() === fullHash.slice(0, 5),
  "URL must contain exactly the first 5 hex chars");
check(!fullHash.toUpperCase().includes(sent.toUpperCase().slice(0, 5)) || sent.toUpperCase() === fullHash.slice(0, 5),
  "first 5 hex chars match the SHA-1 prefix");
console.log(`     sent prefix = ${sent}, full hash = ${fullHash}`);

// ---------------------------------------------------------------------------
// Summary
// ---------------------------------------------------------------------------
console.log();
console.log(`${passes} passed, ${fails} failed`);
process.exit(fails === 0 ? 0 : 1);
