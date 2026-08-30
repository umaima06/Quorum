# STDLIB.md — Quorum

Every place we would normally have reached for a third-party package,
and the standard-library feature we used instead.

| Normally we'd use | Instead we used | Why it works |
|---|---|---|
| `pycryptodome` / `cryptography` (secure randomness) | `secrets` | `secrets.randbelow()` gives cryptographically secure random coefficients for the Shamir polynomial and random private numbers for Diffie-Hellman — the same guarantee a crypto library would provide, without the dependency. |
| `pycryptodome` / `cryptography` (key derivation) | `hashlib.pbkdf2_hmac` | Real, standard KDF (100,000 iterations) turning the raw Diffie-Hellman shared secret into separate encryption and MAC keys, instead of using a single bare hash. |
| `pycryptodome` / `cryptography` (message authentication) | `hmac` + `hashlib` | HMAC-SHA256 tags every encrypted share; `decrypt-share` verifies the tag before decrypting, so tampered ciphertext is rejected outright instead of silently producing garbage. |
| `secretsharing` / `pyshamir` | Hand-rolled `FiniteField`, `Polynomial`, and Shamir's Secret Sharing (split/reconstruct via Lagrange interpolation) | The actual math (GF(p) arithmetic, modular inverse, polynomial evaluation and interpolation) implemented from scratch over a 521-bit prime field — this is the **Package Killer** candidate; see below. |
| `flask` / `express` (serving a small web UI) | `http.server` + `socketserver` | The polynomial visualizer is a single embedded HTML/JS string served straight from Python's built-in HTTP server — no web framework. |
| A transactional email package (e.g. `sendgrid`, `yagmail`) | `smtplib` + `ssl` + `email.message.EmailMessage` | Trustee notifications and owner reminders go out over plain SMTP with TLS, built entirely from stdlib email primitives, with a local `quorum_mailbox.log` fallback if SMTP isn't configured. |
| `click` / `typer` (CLI framework) | `argparse` | All 15 subcommands (`split`, `reconstruct`, `arm`, `checkin`, `watch`, …) are wired up with stdlib `argparse` subparsers — no CLI framework dependency. |
| A task-scheduling package (e.g. `schedule`, `APScheduler`) | `threading` + `time` | The check-in daemon (`watch`) and the `--demo-speed` timer compression are built on stdlib threading and time primitives. |
| A JSON/config library beyond the basics | `json` + `pathlib` | State persistence (`quorum_state.json`) and the audit log read/write straight through stdlib `json` and `pathlib`, no serialization package. |
| A blockchain/audit-log package (e.g. for tamper-evident logging) | Hand-rolled hash-chained log (`hashlib.sha256`) | Chain of Custody links every log entry to the SHA-256 hash of the previous one — the same structural idea behind Certificate Transparency logs, built from a single stdlib hash function. |
| A background job runner / scheduler library (e.g. `APScheduler`, or a separate worker process) | `threading.Thread` (daemon) | The dashboard's "Start Watching" button spins up the check-in daemon as a background thread inside the same process — polling for switch timeout and sending reminder/trigger notifications — instead of requiring a separate process manager or scheduling package. |
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