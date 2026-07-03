// verify_breach_live.mjs — one real call against api.pwnedpasswords.com.
// Network-dependent. Run only when you want to validate the wire format
// against the real service. Skips the rate-limit guard by setting the
// module's lastFireAt far in the past.
//
// Usage:  node scripts/verify_breach_live.mjs

import { webcrypto } from "node:crypto";
if (!globalThis.crypto || !globalThis.crypto.subtle) {
  Object.defineProperty(globalThis, "crypto", { value: webcrypto, configurable: true });
}

const breach = await import("../static/js/breach.js");
// "password" is the canonical HIBP test case: SHA-1 prefix 5BAA6, count > 9M.
console.log("checking 'password' against live HIBP…");
const r = await breach.checkBreach("password");
console.log("result:", r);
if (typeof r.count === "number" && r.count > 0) {
  console.log("OK: HIBP returned a hit");
  process.exit(0);
} else {
  console.log("FAIL: HIBP did not return a hit");
  process.exit(1);
}
