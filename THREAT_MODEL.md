# Threat Model — Quorum

Quorum is a dead-man's-switch secret-sharing tool: it splits a secret into
N shares (K of which are required to reconstruct it) and automatically
notifies trustees if the owner stops checking in. This document states,
plainly, what it protects against and what it does not.

## What it protects against

- **A single trustee going rogue.** No individual trustee can reconstruct
  the secret alone — Shamir's Secret Sharing guarantees that fewer than K
  shares reveal nothing about the secret, not even a partial hint.
- **Accidental loss of the secret.** If the owner becomes unreachable
  (per the intended use case), the dead-man's-switch notifies trustees so
  the secret isn't permanently lost with the owner.
- **A share leaking or being coerced out of one trustee.** The Canary Trap
  mechanism plants decoy shares that look real; using one during
  reconstruction trips a visible alert instead of silently failing or
  succeeding.
- **A trustee's inbox being compromised at any point after setup.** Shares
  are never emailed in plaintext. Each is encrypted using keys derived
  from a Diffie-Hellman exchange via PBKDF2-HMAC-SHA256 (separate
  encryption and MAC keys, 100,000 iterations), with a counter-mode
  keystream that never reuses a block. Every encrypted share carries an
  HMAC-SHA256 tag, verified before decryption (encrypt-then-MAC) — a
  tampered payload is refused outright, never silently decrypted into
  garbage.
- **Silent tampering with the system's own history.** The Chain of Custody
  audit log hash-links every security-relevant event to the one before
  it. Altering any past entry breaks the chain, and `verify-log` detects
  exactly where.
- **Unauthenticated access to the dashboard's data.** Every API endpoint
  — including read-only ones like the switch status, audit log, trustee
  list, and Polynomial Demo — requires a valid owner or trustee session,
  enforced server-side (`_require_role`, checked on both GET and POST
  requests). A request with no valid session gets a 401, regardless of
  whether the corresponding button is visible in the UI.
- **Login credentials stored in plaintext.** Neither the owner's
  passphrase nor any trustee's login credential is ever stored or
  compared as plaintext — both are hashed with PBKDF2-HMAC-SHA256 before
  storage, using a locally generated salt, and verified with
  `hmac.compare_digest` to avoid timing attacks.
- **The Polynomial Demo tab leaking the real secret or exact share
  values.** It visualizes real data from the most recent
  `ShamirSecretSharing.split()` call, but the server only ever sends a
  lossy, normalized (0–1) view of each share's y-value — never the exact
  521-bit value, never the secret itself, and never the polynomial's
  coefficients. Reconstruction inside this tab runs server-side and
  returns only a success/failure message, never the recovered secret. It
  is also visually and functionally separated from the real trustee
  reconstruction workflow in the Secrets tab.
- **The owner forgetting to check in.** `watch` sends the owner a single
  reminder once their window drops below 20% remaining, reducing the
  chance the switch fires by accident. This is a nudge to act, never an
  automatic check-in — it never substitutes for the owner's own
  deliberate confirmation.

## What it does NOT protect against

- **K or more trustees colluding.** By design, K shares are sufficient to
  reconstruct the secret — that's the whole mechanism. If K trustees
  choose to collude, Quorum cannot and does not try to stop them. This
  is an inherent property of threshold secret sharing, not a bug.
- **Compromise of the owner's or a trustee's device.** Encryption
  protects a share in transit and at rest in an inbox — it does not
  protect against malware, keyloggers, or physical access to a device
  that already holds a decrypted share or a private key. It also does
  not verify that a device is trustworthy at initial keypair setup.
- **"Activity" means the owner ran `checkin` — nothing more.** Quorum
  has no way to independently verify the owner is alive, well, or free
  to act; it only knows whether that command was run. This is
  deliberate: automatic signals (laptop login, file-touch activity)
  could be triggered by anyone or anything with access to the machine,
  which would silently weaken what "proof of life" means. The reminder
  system above reduces accidental triggers, but the check-in itself
  remains a manual, deliberate act by design.
- **A `watch` daemon that isn't running.** Whether it's the CLI's `watch`
  command or the dashboard's background thread, something has to
  actually be running for a timeout to be detected. In a real
  deployment this would run as a background service; for this
  submission, that's a disclosed scope boundary.
- **Chain of Custody detects tampering, not deletion.** Editing a past
  log entry breaks the chain and `verify-log` catches it. Deleting the
  entire log file removes the evidence along with it — `verify-log` has
  nothing to detect the absence of.
- **Secrets larger than roughly 65 bytes** don't currently fit in the
  finite field without chunking, which isn't implemented in this
  version.
- **Deployment-scale hardening.** This is a local tool by design, not a
  production or internet-facing service: there's no login
  rate-limiting, the dashboard runs on Python's `http.server` (which
  Python's own documentation scopes to local/demo use), and both the
  state file and the auth salt rely on normal OS file permissions
  rather than additional encryption at rest. None of this is a gap for
  the intended use case — an owner and their trustees each running
  Quorum locally — but it isn't intended to be exposed beyond that.

## On the cryptography used

Per the hackathon's Track E rule against rolling your own cipher, every
cryptographic construction in Quorum is a textbook, publicly vetted
scheme, not an invented one:

- **Shamir's Secret Sharing** (1979) — split/reconstruct via Lagrange
  interpolation over a 521-bit prime field.
- **Diffie-Hellman key exchange** — RFC 3526 Group 14 standard
  parameters, not custom-chosen values.
- **PBKDF2** (`hashlib.pbkdf2_hmac`, 100,000 iterations) for key
  derivation and for hashing the owner passphrase and trustee
  credentials, and **HMAC-SHA256** for message authentication — both
  standard, well-studied constructions.
- A counter-mode-style keystream (`SHA256(key + counter)`), following
  the same principle as standard stream-cipher constructions: no
  keystream block is ever reused.

We compose these primitives; we do not design new ones.

## Summary for judges

Quorum protects against the failure modes named above: losing a secret
with its owner, a single trustee misusing their share, a leaked share
being used, silent tampering with its own audit trail, and
unauthenticated access to its own API. It does not, and does not claim
to, protect against a coordinated K-trustee collusion, a compromised
endpoint, a `watch` daemon that isn't running, or production-scale
deployment — this is a local tool for an owner and their trustees, and
its guarantees are scoped accordingly.