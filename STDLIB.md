# STDLIB.md — Quorum

Every place we would normally have reached for a third-party package,
and the standard-library feature we used instead.

| Normally we'd use | Instead we used | Why it works |
|---|---|---|
| `pycryptodome` / `cryptography` (secure randomness) | `secrets` | `secrets.randbelow()` gives cryptographically secure random coefficients for the Shamir polynomial and random private numbers for Diffie-Hellman; `secrets.token_bytes()` / `secrets.token_hex()` / `secrets.token_urlsafe()` generate the auth salt, session tokens, and trustee credentials — the same guarantee a crypto library would provide, without the dependency. |
| `pycryptodome` / `cryptography` (key derivation) | `hashlib.pbkdf2_hmac` | Real, standard KDF (100,000 iterations) turning the raw Diffie-Hellman shared secret into separate encryption and MAC keys, instead of using a single bare hash. |
| `pycryptodome` / `cryptography` (message authentication) | `hmac` + `hashlib` | HMAC-SHA256 tags every encrypted share; `decrypt-share` verifies the tag before decrypting (`hmac.compare_digest` for constant-time comparison), so tampered ciphertext is rejected outright instead of silently producing garbage. |
| `secretsharing` / `pyshamir` | Hand-rolled `FiniteField`, `Polynomial`, and Shamir's Secret Sharing (split/reconstruct via Lagrange interpolation) | The actual math (GF(p) arithmetic, modular inverse, polynomial evaluation and interpolation) implemented from scratch over a 521-bit prime field — this is the **Package Killer** candidate; see below. |
| `flask` / `express` (serving a small web UI + JSON API) | `http.server` + `socketserver` | The dashboard is a single embedded HTML/JS string served from `BaseHTTPRequestHandler`, with `do_GET`/`do_POST` routing requests to handler methods that call the exact same functions the CLI uses — no web framework. Per the official Zero Dependency 2026 stdlib cheat sheet, `http.server` is explicitly documented as not for production — appropriate here since Quorum's dashboard is a local-only tool, never public-facing.|
| `bcrypt` / `passlib` / `argon2-cffi` (password hashing) | `hashlib.pbkdf2_hmac("sha256", ..., salt, 100_000)` with a per-install random salt (`secrets.token_bytes(16)`, persisted in `quorum_auth_salt.bin`) | The owner's passphrase and every trustee's individually generated login credential are hashed with PBKDF2 before storage/comparison — never stored or compared in plaintext. Verification uses `hmac.compare_digest` to avoid timing attacks. |
| `Flask-Login` / `itsdangerous` / a session-management package | `secrets.token_hex(32)` for session tokens, an in-memory `dict` (`_sessions`) mapping token → role + expiry, and `http.cookies.SimpleCookie` for the `HttpOnly` session cookie | Login issues a random, unguessable session token (4-hour TTL, checked against `time.time()` on every request). Every API endpoint — GET and POST, including read-only status/audit-log/trustee views and the Polynomial Demo — is checked against `ROLE_MAP` server-side before it runs (`_require_role`) — a request with no valid session gets a 401, not just a hidden UI button. |
| A per-user credential/auth package for issuing API keys | `secrets.token_urlsafe(12)` | Each trustee gets a unique login credential generated at `add-trustee` time, emailed to them via the existing `smtplib` notification path, and never shown in the browser response — only its PBKDF2 hash is stored alongside their record. |
| A transactional email package (e.g. `sendgrid`, `yagmail`) | `smtplib` + `ssl` + `email.message.EmailMessage` | Trustee trigger notifications, trustee login credentials, and owner reminders all go out over plain SMTP with TLS, built entirely from stdlib email primitives, with a local `quorum_mailbox.log` fallback if SMTP isn't configured. |
| `click` / `typer` (CLI framework) | `argparse` | All subcommands (`split`, `reconstruct`, `arm`, `checkin`, `watch`, `add-trustee`, `remove-trustee`, …) are wired up with stdlib `argparse` subparsers — no CLI framework dependency. |
| A task-scheduling package (e.g. `schedule`, `APScheduler`) | `threading` + `time` | The check-in daemon (`watch`), the dashboard's background watcher thread, and the `--demo-speed` timer compression are all built on stdlib threading and time primitives. |
| A JSON/config library beyond the basics | `json` + `pathlib` | State persistence (`quorum_state.json`) and the audit log read/write straight through stdlib `json` and `pathlib`, no serialization package. |
| A blockchain/audit-log package (e.g. for tamper-evident logging) | Hand-rolled hash-chained log (`hashlib.sha256`) | Chain of Custody links every log entry to the SHA-256 hash of the previous one — the same structural idea behind Certificate Transparency logs, built from a single stdlib hash function. |
| A background job runner / scheduler library (e.g. `APScheduler`, or a separate worker process) | `threading.Thread(daemon=True)` + `threading.Event` | The dashboard's "Start Watching" / "Stop Watching" buttons control a background daemon thread in the same process (`_watch_loop_background`), with a clean stop signal (`_watch_thread_stop`) — instead of requiring a separate process manager or scheduling package. |
| A URL-opening/launcher utility | `webbrowser` | `quorum.py visualize` auto-opens the dashboard in the user's default browser after the local server starts, without shelling out to OS-specific commands. |

## Package Killer candidate

We're nominating our from-scratch **Shamir's Secret Sharing** implementation
(`FiniteField`, `Polynomial`, and the split/reconstruct logic built on
Lagrange interpolation over a 521-bit prime field) as our Package Killer
entry — it directly replaces what teams would normally reach for from
`secretsharing` or `pycryptodome`'s secret-sharing utilities, both real,
installed packages.

## A note on what we did *not* invent

Per the "don't roll your own crypto" rule, we did not invent any new
cryptographic primitive. Every construction above is a textbook, publicly
vetted scheme (Shamir's Secret Sharing, 1979; Diffie-Hellman with RFC 3526
Group 14 standard parameters; PBKDF2; HMAC; counter-mode-style keystream
generation) — we implemented the *composition* of these ourselves from
stdlib primitives, we did not design new math. This distinction is also
covered in our threat model doc.