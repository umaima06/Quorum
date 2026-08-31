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
  are never emailed in plaintext. Each is encrypted with a key derived
  from a Diffie-Hellman exchange (via `hashlib.pbkdf2_hmac`) and carries
  an HMAC-SHA256 tag; `decrypt-share` refuses tampered ciphertext outright
  rather than producing garbage output.
- **Silent tampering with the system's own history.** The Chain of Custody
  audit log hash-links every security-relevant event to the one before
  it. Altering any past entry breaks the chain, and `verify-log` detects
  exactly where.
- **Unauthenticated access to the dashboard's data via direct API calls.**
  Every API endpoint — including read-only ones like the switch status,
  audit log, and trustee list, and the Polynomial Demo — requires a
  valid owner or trustee session server-side (`_require_role`, checked
  in both `do_GET` and `do_POST`). A `curl` call with no session gets a
  401, the same as clicking a hidden button in the UI would.
  
## What it does NOT protect against

- **K or more trustees colluding.** By design, K shares are sufficient to
  reconstruct the secret — that's the whole mechanism. If K trustees
  choose to collude (rather than being individually coerced or
  compromised), Quorum cannot and does not try to stop them. This is an
  inherent property of threshold secret sharing, not a bug.
- **Compromise of the owner's or a trustee's device itself.** Encryption
  protects a share in transit and at rest in an inbox — it does not
  protect against malware, keyloggers, or physical access to a device
  that already holds a decrypted share or a private key.
- **Side-channel attacks on the machine while Quorum is running** (e.g.
  timing attacks, memory scraping). Quorum is a straightforward CLI tool;
  it makes no special hardening claims against sophisticated local
  attackers with access to the running process.
- **"Activity" only means the owner ran `checkin`.** Quorum has no way to
  independently verify the owner is alive, well, or free to act — it only
  knows whether the `checkin` command was run. This is a deliberate
  design choice, not an oversight: we considered tying check-ins to
  passive signals (laptop login, file-touch activity) and rejected both,
  because either could be triggered by anyone or anything with access to
  the machine, silently weakening what "proof of life" actually means.
  Manual, deliberate check-in mirrors how real commercial dead-man's-switch
  products are designed.
- **`watch` must be running continuously for the switch to actually
  fire.** If no machine is running the `watch` daemon, a timeout will not
  be detected and no notification will go out. In a real deployment this
  needs to run as a background service, not a terminal window left open —
  for the hackathon demo, this limitation is intentional and disclosed
  rather than hidden.
- **Chain of Custody detects tampering; it does not prevent deletion.**
  Someone with file-system access to `quorum_audit.log` who deletes the
  file entirely (rather than editing an entry) removes the evidence along
  with the log. `verify-log` can prove an entry was *altered*; it cannot
  prove an entry was *removed* if the whole file is gone.
- **Two separate integrity mechanisms protect two separate things.** The
  XOR/HMAC encryption on shares protects the *ciphertext of a share in
  transit*. The Chain of Custody hash chain protects the *audit log
  itself*. Neither substitutes for the other, and a judge or reviewer
  should not conflate them.
- **Secrets larger than roughly 65 bytes do not currently fit in the
  finite field without chunking.** This is a known constraint of the
  current implementation, not addressed in this version.
- **Passphrase/key distribution still has a boundary.** Diffie-Hellman
  removes the need for an in-person or out-of-band passphrase exchange —
  only public values ever travel over email — but the initial keypair
  generation and exchange still assumes the owner's and trustee's own
  devices are trustworthy at setup time. Quorum cannot verify that
  independently.

## On the cryptography used

Per the hackathon's Track E rule against rolling your own cipher, every
cryptographic construction in Quorum is a textbook, publicly vetted
scheme, not an invented one:

- **Shamir's Secret Sharing** (1979) — split/reconstruct via Lagrange
  interpolation over a 521-bit prime field.
- **Diffie-Hellman key exchange** — RFC 3526 Group 14 standard
  parameters, not custom-chosen values.
- **PBKDF2** (`hashlib.pbkdf2_hmac`, 100,000 iterations) for key
  derivation, and **HMAC-SHA256** for message authentication — both
  standard, well-studied constructions.
- The counter-mode-style keystream (`SHA256(key + counter)`) follows the
  same principle as standard stream-cipher constructions: never reuse a
  keystream block, which was the specific weakness in an earlier version
  of this project that the hackathon organizer flagged and we corrected.

We compose these primitives; we do not design new ones.

## Summary for judges

Quorum protects against the failure modes it explicitly names above:
losing a secret with its owner, a single trustee misusing their share, a
leaked share being used, and silent tampering with its own audit trail.
It does not, and does not claim to, protect against a coordinated
K-trustee collusion, a compromised endpoint, or a `watch` daemon that
simply isn't running. We would rather state these boundaries plainly than
overclaim security the tool doesn't actually provide.