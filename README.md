# Secure Password Generator

A web-based, cryptographically secure password generator with entropy analysis, crack-time estimation, a local password auditor, and an on-device history (no server-side storage).

The UI runs in the browser; all generation and auditing happens client-side. The Flask backend is a thin wrapper that also exposes a JSON API for programmatic use.

> The previous version of this project was a single-file Tkinter desktop app. It is preserved under [`archive/`](archive/) for reference.

---

## Features

- **Cryptographic randomness** — `crypto.getRandomValues` in the browser and Python's `secrets` on the server, with rejection sampling to avoid modulo bias.
- **Configurable generation** — length 4–128, batch size 1–50, four character categories (uppercase, lowercase, numbers, special), and an "avoid ambiguous" filter that strips `0/O`, `1/l/I`, brackets, quotes, etc.
- **Category guarantee** — every selected category appears at least once in the output.
- **Strength analysis** — 4-tier label (Weak / Medium / Strong / Very Strong) and a NIST SP 800-63B-inspired 0–8 score with a visual bar.
- **Entropy & crack-time** — Shannon-style entropy (`H = L · log₂(pool)`) and a human-readable time-to-crack estimate at 10 billion guesses/sec.
- **Password auditor** — paste your own password to get length, category, repetition, sequence, keyboard-row, and common-leet warnings, plus a live k-anonymity breach check.
- **Have I Been Pwned (k-anonymity)** — the password is hashed with SHA-1 locally via Web Crypto; only the first 5 hex chars of the digest are sent to `api.pwnedpasswords.com`, and the rest of the lookup is done against the response. Enable on the server with `SPG_ENABLE_HIBP=1` (off by default so the CSP stays self-hosted out of the box).
- **Local history** — every generated password is stored in `localStorage` (key `spg.history.v1`, capped at 200 entries). Export to JSON, import from JSON, or clear. Actions live in the card header for quick access.
- **Adaptive results card** — collapses to a compact empty state and grows naturally as passwords are generated.
- **Password safety tips** — a collapsible accordion with best-practice reminders and a list of keyboard shortcuts.
- **Dark / light theme** — toggle in the header; respects the OS `prefers-color-scheme` on first load and remembers the choice in `localStorage`.
- **Clipboard safety** — copies are auto-cleared from the clipboard after 30 s; results also auto-wipe from the DOM after 30 s when the tab is hidden.
- **Keyboard shortcuts** — `G` generate, `C` copy first, `?` show hint, `Esc` collapse the tips accordion.
- **Hardened HTTP** — strict CSP (self-hosted only, HIBP opt-in), `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `Permissions-Policy` lockdown, 64 KB request cap.

---

## Project structure

```
SecurePasswordGenerator/
├── app.py                       # Flask app factory, routes, security headers
├── password_core.py             # Pure Python generation, validation, entropy
├── requirements.txt
├── templates/
│   └── index.html               # Single-page UI
├── static/
│   ├── css/
│   │   ├── main.css             # Theme variables, layout, header, tips
│   │   └── components.css       # Cards, form controls, strength bar, toasts, modal
│   ├── js/
│   │   ├── app.js               # Bootstrap
│   │   ├── crypto.js            # Web Crypto-backed generator
│   │   ├── strength.js          # Entropy, NIST score, zxcvbn-lite auditor, SHA-1
│   │   ├── breach.js            # HIBP k-anonymity range lookup
│   │   ├── history.js           # localStorage CRUD + JSON import/export
│   │   └── ui.js                # DOM wiring, toasts, modal, clipboard, theme
│   └── img/
│       └── favicon.svg
└── archive/
    ├── main.py                  # Original Tkinter desktop app (preserved)
    └── generated_passwords.txt  # Sample output from the Tkinter version
```

`archive/` is preserved for reference only — the shipped app does not depend on it.

---

## Quick start

```bash
# from the project root
python -m venv .venv
.venv\Scripts\activate            # Windows
# source .venv/bin/activate       # macOS / Linux
pip install -r requirements.txt
python app.py
```

Open http://127.0.0.1:5000/.

Environment variables (all optional):

| Variable          | Default      | Purpose                                                            |
|-------------------|--------------|--------------------------------------------------------------------|
| `HOST`            | `127.0.0.1`  | Bind address                                                       |
| `PORT`            | `5000`       | Bind port                                                          |
| `FLASK_DEBUG`     | `0`          | Set to `1` for debug mode + auto-reload                            |
| `APP_VERSION`     | `1.0.0`      | Shown in the UI header version badge                               |
| `SPG_ENABLE_HIBP` | unset        | Set to `1` to allow the browser to call `api.pwnedpasswords.com`   |

---

## HTTP API

All endpoints return JSON. Errors come back as `{"error": "..."}` with a 4xx/5xx status.

### `GET /api/health`

Liveness probe.

```json
{ "status": "ok" }
```

### `POST /api/generate`

Request body:

```json
{
  "length": 16,
  "count": 1,
  "categories": ["uppercase", "lowercase", "numbers", "special"],
  "avoid_ambiguous": false
}
```

Response:

```json
{
  "passwords": ["aB3$kQ9..."],
  "stats": [
    {
      "length": 16,
      "uppercase": 4, "lowercase": 5, "digits": 4, "special": 3,
      "unique_chars": 14,
      "entropy_bits": 103.2,
      "crack_time": "Centuries upon centuries",
      "strength": "Very Strong"
    }
  ]
}
```

Validation: `length ∈ [4, 128]`, `count ∈ [1, 50]`, at least one known category.

### `POST /api/strength`

Request body:

```json
{ "password": "hunter2", "categories": ["uppercase", "lowercase", "numbers", "special"] }
```

Response: a single stats object (same shape as the elements of `stats` above).

---

## Core module (`password_core.py`)

Pure Python, no web framework dependencies. Re-usable from any front end.

```python
from password_core import (
    CHAR_SETS, AMBIGUOUS_CHARS,
    generate_password, validate_inputs,
    password_stats, calculate_strength,
    calculate_entropy, estimate_crack_time, pool_size,
)

# 16-char password with all four categories
pwd = generate_password(16, ["uppercase", "lowercase", "numbers", "special"])
stats = password_stats(pwd, ["uppercase", "lowercase", "numbers", "special"])
```

Algorithm:

1. Seed one mandatory character from each selected category.
2. Fill the remaining slots from the union pool using `secrets.choice`.
3. Shuffle with `secrets.SystemRandom` so the seeded characters are randomly positioned.

When `avoid_ambiguous=True`, the seed for each category is drawn from that category's pool with ambiguous characters removed, falling back to the union pool for any category that becomes empty.

---

## Browser crypto (`static/js/crypto.js`)

Mirrors the Python generator using the Web Crypto API. Uses a rejection-sampling loop (largest multiple of `max` that fits in 2³²) so all `Uint32` outputs are uniformly distributed across `[0, max)`. The Fisher–Yates shuffle is also backed by `crypto.getRandomValues`.

## Strength & audit (`static/js/strength.js`)

- `calculateStrength(pwd)` — Weak / Medium / Strong / Very Strong, same heuristic as the Python side.
- `calculateEntropy(pwd, pool)` and `estimateCrackTime(bits)`.
- `nistScore(pwd)` — 0–8 score inspired by NIST SP 800-63B: points for category diversity, length thresholds at 8/12/15, and a deduction for obvious patterns.
- `analyzePassword(pwd)` — returns `[{type, message}]` of `warn` / `suggestion` / `positive` feedback covering length, category mix, repetition (`(.)\1{2,}`), numeric/alpha sequences, common keyboard rows, and a small blocklist of common leet fragments.
- `sha1Hex(str)` — SHA-1 via `crypto.subtle.digest` (used by the breach check).

## Breach check (`static/js/breach.js`)

- `checkBreach(password)` and `abortBreach()`.
- Hashes the password locally with SHA-1, sends only the first 5 hex chars to `https://api.pwnedpasswords.com/range/{prefix}`, and searches the returned suffix list locally for the remaining 35 chars.
- Includes a 250 ms rate limit and an `AbortController` that cancels any in-flight request when a new one starts or when the user clears the input (so stale results never paint).

The browser is only allowed to make this cross-origin request when the server was started with `SPG_ENABLE_HIBP=1`, which widens the `connect-src` directive in the CSP.

## History (`static/js/history.js`)

Stored in `localStorage` under `spg.history.v1`. Capped at 200 entries. De-dupes by password value. `importJSON` merges by password and ignores entries without a non-empty string `password`. The card's Export / Import / Clear actions live in the card header for compactness.

---

## Security notes

- **Randomness**: client uses `crypto.getRandomValues`; server uses `secrets`. Both rejection-sample to eliminate modulo bias.
- **No external requests by default**: CSP locks `default-src`, `script-src`, `style-src`, `img-src`, `font-src` to `'self'`, and `connect-src` to `'self'`. Set `SPG_ENABLE_HIBP=1` to allow the k-anonymity lookup against `api.pwnedpasswords.com`; the password itself is never sent.
- **No telemetry**: history never leaves the browser; the audit input never leaves the browser; the server never logs the password value.
- **Clipboard**: copied passwords are auto-cleared from the clipboard after 30 s.
- **Tab hidden**: results are wiped from the DOM after 30 s of the tab being hidden (defense-in-depth for kiosk demos).
- **Request cap**: 64 KB max request body.

---

## License

Personal project. No license file is included — treat as all rights reserved unless a license is added later.
