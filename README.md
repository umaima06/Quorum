# Quorum

**A stdlib-only dead-man's-switch for secret sharing.**

> "If I don't check in for 30 days, my co-founder and my lawyer each get
> half of what they need to unlock my company's crypto wallet — but
> neither one alone can touch it."

Quorum splits a secret into N shares (K of which are needed to
reconstruct it) using Shamir's Secret Sharing, distributes shares to
trustees using Diffie-Hellman key exchange, and automatically notifies
those trustees if the owner stops checking in. Every security-relevant
action is recorded in a hash-chained, tamper-evident audit log.

Built for **Zero Dependency 2026 — Track E (Security & Crypto Utilities)**.
Zero third-party runtime dependencies — Python standard library only.

---

## Features

- **Shamir's Secret Sharing**, implemented from scratch (`FiniteField`,
  `Polynomial`, Lagrange interpolation) over a 521-bit prime field.
- **Canary Trap** — decoy shares that trigger a visible alert if used
  during reconstruction, signalling a leaked or coerced share.
- **Diffie-Hellman key exchange** (RFC 3526 Group 14) for secure trustee
  share distribution, with PBKDF2-derived keys and encrypt-then-MAC
  (HMAC-SHA256) authenticated encryption.
- **Chain of Custody** — a hash-chained audit log; any tampering with
  past history is cryptographically detectable via `verify-log`.
- **Dead-man's-switch daemon** — arm a check-in window, get reminded
  before it expires, and have trustees automatically notified (real
  email via `smtplib`, with a safe local-log fallback) if it does.
- **Owner/Trustee authentication** — the dashboard requires logging in
  with a role-specific passphrase. The server verifies the passphrase
  and issues a session; the UI and *every* API endpoint enforce role
  server-side, including read-only endpoints (status, audit log,
  trustee list, secrets list) and the Polynomial Demo — not just the
  state-changing ones, and not just hidden buttons in the UI. Login is
  once per session (a cookie carries it across tabs and requests for up
  to 4 hours) — you are not asked to re-authenticate per tab or per
  action. Each trustee is issued their own credential when they're
  registered, emailed to them, and reusable for future logins.
- **A full local web dashboard** — split secrets, manage trustees,
  generate/encrypt/decrypt keys, watch the switch countdown live, and
  view the audit log's hash chain and a real polynomial-reconstruction
  visualization — all in the browser, built entirely on stdlib
  `http.server` (no frontend or backend framework).

---

## Quick start

No installation, no dependencies. Requires only Python 3.

```bash
python quorum.py --help
```

### One-command build

There's no compile step (pure Python) — "build" means confirming the
source is syntactically valid:

```bash
python -m py_compile quorum.py
```

### Launch the dashboard

```bash
python quorum.py visualize
```

Opens a local control panel in your browser at `http://localhost:8420`.
You'll be asked to log in as **Owner** or **Trustee** with the
corresponding passphrase before the dashboard shows anything — session
and role are enforced by the server, not just the UI.

- **Owner** login unlocks: Split, Arm/Check-in, Add/Remove Trustee,
  Encrypt Share.
- **Trustee** login unlocks: Decrypt Share, Reconstruct, and shows an
  **Assigned Secret** card naming exactly which secret label their
  share belongs to.

Note: sessions and the Polynomial Demo tab's current data are held in
memory only — restarting the server clears them (you'll see "No secret
has been split yet" on the demo tab after a restart even if you've
split plenty before). This is expected behavior, not a bug. The
Polynomial Demo tab is clearly marked "🎓 Educational Demo" in the UI —
it's a visualization aid, not the trustee reconstruction workflow, which
lives in the Secrets tab and is labeled "🔐 Real reconstruction".

---

## CLI usage

```bash
# Split a secret into 5 shares, 3 needed to reconstruct, 1 decoy canary
python quorum.py split "my-secret" --label "Wallet seed" --n 5 --k 3 --canaries 1

# Reconstruct from 3 real shares
python quorum.py reconstruct 1:<share> 2:<share> 3:<share> --length <byte-length>

# Generate a Diffie-Hellman keypair
python quorum.py keygen

# Encrypt a share for a trustee (owner runs this)
python quorum.py encrypt-share --my-private <priv> --their-public <pub> --share "1:<share>"

# Decrypt a received share (trustee runs this)
python quorum.py decrypt-share --my-private <priv> --their-public <pub> --encrypted-hex <hex>

# Register / remove a trustee
python quorum.py add-trustee --name "Name" --email "a@b.com" --label "Wallet seed" --encrypted-hex <hex>
python quorum.py remove-trustee --name "Name"

# Arm the switch (--demo-speed treats --days as seconds, for live demos)
python quorum.py arm --days 30 --demo-speed
python quorum.py checkin
python quorum.py status
python quorum.py watch          # foreground daemon — reminders + trigger fire while this runs

# Chain of Custody
python quorum.py show-log
python quorum.py verify-log

# Reproducible build proof
python quorum.py build-check --file quorum.py
```

Full command reference: `python quorum.py --help`

---

## Configuration (optional — real email)

To send real trustee/reminder emails instead of falling back to a local
log file, create a `quorum.env` file (never committed — see `.gitignore`):

```dotenv
QUORUM_SMTP_HOST=smtp.gmail.com
QUORUM_SMTP_PORT=587
QUORUM_SMTP_USER=your-email@gmail.com
QUORUM_SMTP_PASS=your-16-character-app-password
```

Without this file, notifications are written to `quorum_mailbox.log`
instead — nothing breaks, no crash, no network dependency required.

---
## A note on `http.server`

The dashboard is served using Python's built-in `http.server`. Python's
own documentation describes this module as suitable for local and demo
use, not for production or public-facing deployment. That's an
intentional fit here — Quorum's dashboard is meant to run locally, on
the owner's or a trustee's own machine, never as a public-facing
service — so this is the correct tool for the job, not a shortcut.

---
## Zero-dependency proof

```bash
python -m py_compile quorum.py   # confirms the file is valid, standalone Python
type deps-proof.txt              # every import, checked against the stdlib
```

`requirements.txt` is intentionally empty — see `deps-proof.txt` for the
complete, verifiable list of stdlib-only imports.

---

## Documentation

- [`STDLIB.md`](./STDLIB.md) — every package we'd normally use, and the
  standard-library feature that replaced it.
- [`THREAT_MODEL.md`](./THREAT_MODEL.md) — what Quorum protects against,
  what it explicitly does not, and why.
- [`tests/test_quorum.py`](./tests/test_quorum.py) — black-box CLI test
  suite covering the core crypto, Canary Trap, tamper detection, and the
  reproducible-build proof.

---

## Reproducible Build

`quorum.py` is pure Python with no compile step — "build" means verifying
the source is byte-identical across builds. We hashed the file twice,
independently, and confirmed the outputs match:

Build 1 SHA-256: `a0903ab6596e0ce60d229d2ff29b91df3d45ef9afd47807b684ece8148f729bf`
Build 2 SHA-256: `a0903ab6596e0ce60d229d2ff29b91df3d45ef9afd47807b684ece8148f729bf`

Reproduce this yourself:
```
python quorum.py build-check --file quorum.py
```

---

## Team

Umaima · Zunairah · Alizah
Track E — Security & Crypto Utilities · Zero Dependency 2026