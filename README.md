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
- **A full local web dashboard** — split secrets, manage trustees,
  generate/encrypt/decrypt keys, watch the switch countdown live, and
  visualize the audit log's hash chain and the polynomial reconstruction
  — all in the browser, built entirely on stdlib `http.server` (no
  frontend or backend framework).
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
 
Opens a local control panel in your browser at `http://localhost:8420`
— split secrets, manage trustees, arm the switch, and watch the audit
log update live, without touching the CLI again.
 
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
 
Build 1 SHA-256: `SHA-256(quorum.py): a0903ab6596e0ce60d229d2ff29b91df3d45ef9afd47807b684ece8148f729bf`
Build 2 SHA-256: `SHA-256(quorum.py): a0903ab6596e0ce60d229d2ff29b91df3d45ef9afd47807b684ece8148f729bf`
 
Reproduce this yourself:
```
python quorum.py build-check --file quorum.py
```
 
---
 
## Team
 
Umaima · Zunairah · Alizah
Track E — Security & Crypto Utilities · Zero Dependency 2026