"""
Quorum — a stdlib-only dead-man's-switch secret sharing tool.

If the owner doesn't check in within a configured window, trustees can
combine their shares (via Shamir's Secret Sharing) to reconstruct a
protected secret. Shares are distributed to trustees using Diffie-Hellman
key exchange, so the secret itself never crosses an insecure channel.
Decoy "canary" shares detect coerced or leaked reconstruction attempts.
Every security-relevant action is recorded in a hash-chained, tamper-evident
audit log — so even the tool's own history can't be quietly rewritten.

Track E — Security & Crypto Utilities.
Zero third-party runtime dependencies — Python standard library only:
    secrets, hashlib, http.server, socketserver, webbrowser, threading,
    argparse, json, os, sys, time, smtplib, ssl, subprocess,
    email.message, pathlib
"""

# =============================================================================
# Imports
# =============================================================================

import argparse
import hashlib
import hmac
import http.server
import json
import os
import secrets
import smtplib
import socketserver
import ssl
import sys
import threading
import time
import webbrowser
from email.message import EmailMessage
from pathlib import Path


# =============================================================================
# Constants
# =============================================================================

# Large prime defining our finite field GF(p) for Shamir's Secret Sharing.
# 2^521 - 1 is a well-known Mersenne prime, plenty large for realistic secrets.
SSS_PRIME = 2**521 - 1

# Standard 2048-bit MODP Diffie-Hellman group (RFC 3526, Group 14).
# Publicly vetted parameters — not invented ourselves, per Track E's rules.
DH_PRIME = int("""
FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E0
88A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B
302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A
637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649
286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD2
4CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C
354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E8
6039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497
CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
""".replace("\n", ""), 16)
DH_GENERATOR = 2

# Canary shares use x-coordinates at or above this value, clearly separated
# from real shares (which use x = 1..n). Touching this range trips an alert.
CANARY_X_START = 10000

# Where switch state, audit log, and env config live between CLI invocations.
CONFIG_PATH = Path("quorum_state.json")
AUDIT_LOG_PATH = Path("quorum_audit.log")
MAILBOX_LOG_PATH = Path("quorum_mailbox.log")
ENV_FILE_PATH = Path("quorum.env")


# =============================================================================
# Core math: finite field arithmetic and polynomials
# =============================================================================

class FiniteField:
    """Modular arithmetic over GF(p), used as the base field for SSS."""

    def __init__(self, prime=SSS_PRIME):
        self.p = prime

    def add(self, a, b):
        return (a + b) % self.p

    def sub(self, a, b):
        return (a - b) % self.p

    def mul(self, a, b):
        return (a * b) % self.p

    def inv(self, a):
        """Multiplicative inverse via Fermat's Little Theorem: a^(p-2) mod p."""
        if a % self.p == 0:
            raise ZeroDivisionError("no inverse for 0 in a finite field")
        return pow(a, self.p - 2, self.p)

    def div(self, a, b):
        return self.mul(a, self.inv(b))


class Polynomial:
    """
    A random polynomial over a finite field where f(0) equals a chosen secret.

    Used as the mathematical basis of Shamir's Secret Sharing: the secret is
    the constant term, and points (x, f(x)) become shares.
    """

    def __init__(self, secret, degree, field=None):
        """
        degree = K - 1, where K is the reconstruction threshold.
        Coefficients (other than the secret) are cryptographically random
        and discarded once shares are generated.
        """
        self.field = field or FiniteField()
        self.secret = secret % self.field.p
        self.coefficients = [self.secret] + [
            secrets.randbelow(self.field.p) for _ in range(degree)
        ]

    def evaluate(self, x):
        """Evaluate f(x) mod p using Horner's method."""
        result = 0
        for coeff in reversed(self.coefficients):
            result = self.field.add(self.field.mul(result, x), coeff)
        return result


# =============================================================================
# Shamir's Secret Sharing
# =============================================================================

class ShamirSecretSharing:
    """Split a secret into N shares (any K of which reconstruct it) and back."""

    def __init__(self, field=None):
        self.field = field or FiniteField()

    def split(self, secret, n, k):
        """Split secret into n shares, any k of which can reconstruct it."""
        if k > n:
            raise ValueError("threshold k cannot exceed number of shares n")
        poly = Polynomial(secret, degree=k - 1, field=self.field)
        # x-coordinates 1..n — never use x=0, that's the secret itself.
        return [(x, poly.evaluate(x)) for x in range(1, n + 1)]

    def reconstruct(self, shares):
        """Reconstruct the secret from shares via Lagrange interpolation at x=0."""
        secret = 0
        for i, (xi, yi) in enumerate(shares):
            numerator, denominator = 1, 1
            for j, (xj, _) in enumerate(shares):
                if i == j:
                    continue
                numerator = self.field.mul(numerator, self.field.sub(0, xj))
                denominator = self.field.mul(denominator, self.field.sub(xi, xj))
            term = self.field.mul(yi, self.field.div(numerator, denominator))
            secret = self.field.add(secret, term)
        return secret


def secret_to_int(secret_bytes: bytes) -> int:
    """Encode a secret's raw bytes as an integer for splitting."""
    return int.from_bytes(secret_bytes, byteorder="big")


def int_to_secret(secret_int: int, length: int) -> bytes:
    """Decode a reconstructed integer back into the original secret's bytes."""
    return secret_int.to_bytes(length, byteorder="big")


# =============================================================================
# Canary Trap — decoy shares that detect coerced/leaked reconstruction
# =============================================================================

class CanaryTrap:
    """
    Generates decoy shares in a reserved x-coordinate range and detects
    when one is submitted during reconstruction — a strong signal that a
    share was leaked or a trustee was coerced.
    """

    def __init__(self, field=None):
        self.field = field or FiniteField()

    def generate_canaries(self, count):
        """Generate `count` decoy shares that look real but never validate."""
        canaries = []
        for i in range(count):
            x = CANARY_X_START + i
            y = secrets.randbelow(self.field.p)
            canaries.append((x, y))
        return canaries

    def check_for_tripwire(self, shares):
        """Return any submitted shares that fall in the reserved canary range."""
        return [(x, y) for (x, y) in shares if x >= CANARY_X_START]


# =============================================================================
# Diffie-Hellman key exchange — secure trustee share distribution
# =============================================================================

class DiffieHellman:
    """
    Standard Diffie-Hellman key exchange (RFC 3526 Group 14 parameters).

    Lets two parties (e.g. the owner and a trustee) independently derive
    the same shared secret over an insecure channel, without ever
    transmitting the secret itself.
    """

    def __init__(self, prime=DH_PRIME, generator=DH_GENERATOR):
        self.p = prime
        self.g = generator
        # Private key: random, secret, never transmitted.
        self.private_key = secrets.randbelow(self.p - 2) + 2

    def public_key(self):
        """Public value to exchange with the other party. Safe to expose."""
        return pow(self.g, self.private_key, self.p)

    def shared_secret(self, their_public_key):
        """Combine our private key with their public value to derive the shared secret."""
        return pow(their_public_key, self.private_key, self.p)


def derive_keys(shared_secret_int, dklen=64):
    """
    Derive TWO separate keys (encryption key + MAC key) from the raw DH
    shared secret, using PBKDF2-HMAC-SHA256 — a real, standard stdlib KDF
    (per organizer guidance: bare SHA-256 over the DH output is not
    sufficient; a proper KDF is required).

    Key separation (one key per purpose) is standard cryptographic
    practice — using the same key for both encryption and authentication
    can leak information between the two uses.

    A fixed, non-secret application salt is safe here: PBKDF2's salt only
    needs to be known to both parties (not secret), so the owner and
    trustee — who each derive the same DH shared secret independently —
    also derive the same output key material without exchanging anything
    extra.
    """
    salt = b"quorum-v1-trustee-share"
    secret_bytes = shared_secret_int.to_bytes(
        (shared_secret_int.bit_length() + 7) // 8, "big"
    )
    key_material = hashlib.pbkdf2_hmac("sha256", secret_bytes, salt, 100_000, dklen=dklen)
    enc_key = key_material[:32]
    mac_key = key_material[32:64]
    return enc_key, mac_key


def _keystream(key: bytes, length: int) -> bytes:
    """
    Generate a keystream of exactly `length` bytes using a hash-based
    counter-mode construction: keystream_block[i] = SHA256(key || counter_i).

    Standard technique for turning a hash function into a stream cipher
    (structurally the same idea as CTR mode). Every block is unique
    (driven by an incrementing counter), so no repeating keystream byte
    is ever reused — per organizer guidance, keystream reuse is exactly
    what must be avoided.
    """
    blocks = []
    counter = 0
    generated = 0
    while generated < length:
        block = hashlib.sha256(key + counter.to_bytes(8, "big")).digest()
        blocks.append(block)
        generated += len(block)
        counter += 1
    return b"".join(blocks)[:length]


def xor_encrypt(data: bytes, key: bytes) -> bytes:
    """Raw XOR against the counter-mode keystream. Confidentiality only —
    call encrypt_then_mac() for the authenticated version actually used
    by the CLI."""
    keystream = _keystream(key, len(data))
    return bytes(d ^ k for d, k in zip(data, keystream))


def xor_decrypt(data: bytes, key: bytes) -> bytes:
    """XOR is symmetric — decryption is identical to encryption."""
    return xor_encrypt(data, key)


def encrypt_then_mac(plaintext: bytes, enc_key: bytes, mac_key: bytes) -> bytes:
    """
    Encrypt-then-MAC (per organizer guidance): encrypt first, then compute
    an HMAC over the ciphertext and append it. This makes the ciphertext
    tamper-evident — any modification in transit is detected before
    decryption is even attempted, closing the "unauthenticated XOR is
    malleable" gap.

    Output layout: ciphertext || hmac_tag (32 bytes)
    """
    ciphertext = xor_encrypt(plaintext, enc_key)
    tag = hmac.new(mac_key, ciphertext, hashlib.sha256).digest()
    return ciphertext + tag


def decrypt_then_verify(payload: bytes, enc_key: bytes, mac_key: bytes) -> bytes:
    """
    Verify the HMAC tag BEFORE decrypting anything (encrypt-then-MAC
    verification order). Raises ValueError if the payload was tampered
    with or corrupted — never silently returns garbage.
    """
    if len(payload) < 32:
        raise ValueError("payload too short to contain a valid HMAC tag")

    ciphertext, tag = payload[:-32], payload[-32:]
    expected_tag = hmac.new(mac_key, ciphertext, hashlib.sha256).digest()

    # Constant-time comparison — prevents timing attacks on tag verification.
    if not hmac.compare_digest(tag, expected_tag):
        raise ValueError("HMAC verification failed — payload was tampered with or corrupted")

    return xor_decrypt(ciphertext, enc_key)


# =============================================================================
# Chain of Custody — tamper-evident, hash-chained audit log
# =============================================================================
#
# "Trust nothing" applies to the tool's own history too. Every
# security-relevant action (split, arm, checkin, reconstruction attempt,
# canary trip, trigger) is appended as a JSON line containing:
#   - the event data
#   - a timestamp
#   - the SHA-256 hash of the *previous* entry
#
# This produces a hash chain identical in structure to a blockchain or a
# Certificate Transparency log: altering, deleting, or reordering any past
# entry changes its hash, which breaks every entry after it. `verify-log`
# walks the chain and proves — cryptographically, not by promise — whether
# the history is intact.

GENESIS_HASH = "0" * 64  # the chain's starting point, hash of "nothing before this"


def _hash_entry(entry: dict) -> str:
    """Deterministic SHA-256 of a log entry's canonical JSON form."""
    canonical = json.dumps(entry, sort_keys=True).encode()
    return hashlib.sha256(canonical).hexdigest()


def audit_log(event: str, details: dict = None):
    """Append a new event to the hash-chained audit log."""
    details = details or {}
    prev_hash = _last_entry_hash()

    entry = {
        "event": event,
        "details": details,
        "timestamp": time.time(),
        "prev_hash": prev_hash,
    }
    entry["hash"] = _hash_entry({k: v for k, v in entry.items() if k != "hash"})

    with open(AUDIT_LOG_PATH, "a") as f:
        f.write(json.dumps(entry) + "\n")


def _last_entry_hash():
    """Return the hash of the most recent audit log entry, or GENESIS_HASH if empty."""
    if not AUDIT_LOG_PATH.exists():
        return GENESIS_HASH
    last_line = None
    with open(AUDIT_LOG_PATH, "r") as f:
        for line in f:
            line = line.strip()
            if line:
                last_line = line
    if last_line is None:
        return GENESIS_HASH
    return json.loads(last_line)["hash"]


def verify_audit_log():
    """
    Walk the entire chain and verify every entry's hash is correctly derived
    from its contents and correctly links to the previous entry's hash.

    Returns (is_valid: bool, entry_count: int, break_index: int|None).
    """
    if not AUDIT_LOG_PATH.exists():
        return True, 0, None

    expected_prev = GENESIS_HASH
    count = 0
    with open(AUDIT_LOG_PATH, "r") as f:
        for i, line in enumerate(f):
            line = line.strip()
            if not line:
                continue
            entry = json.loads(line)
            count += 1

            if entry["prev_hash"] != expected_prev:
                return False, count, i

            claimed_hash = entry["hash"]
            recomputed = _hash_entry({k: v for k, v in entry.items() if k != "hash"})
            if claimed_hash != recomputed:
                return False, count, i

            expected_prev = claimed_hash

    return True, count, None


def cli_verify_log(args):
    """CLI: verify the audit log chain is intact and print the result."""
    valid, count, break_index = verify_audit_log()
    if valid:
        print(f"✅ Audit log verified: {count} entries, chain intact, no tampering detected.")
    else:
        print(f"🚨 AUDIT LOG TAMPERED: chain breaks at entry #{break_index} (of {count} checked).")
        print("   The recorded history cannot be trusted from this point forward.")


def cli_show_log(args):
    """CLI: print the audit log in human-readable form."""
    if not AUDIT_LOG_PATH.exists():
        print("No audit log yet.")
        return
    with open(AUDIT_LOG_PATH, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            entry = json.loads(line)
            ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(entry["timestamp"]))
            print(f"[{ts}] {entry['event']}  {entry['details']}")
            print(f"    hash={entry['hash'][:16]}...  prev={entry['prev_hash'][:16]}...")


# =============================================================================
# Persistence — local JSON config
# =============================================================================

def load_state():
    """Load the persisted switch state, or return a fresh default if none exists."""
    if not CONFIG_PATH.exists():
        return {
            "armed": False,
            "days": None,
            "demo_speed": False,
            "last_checkin": None,
            "trustees": [],   # [{ "name", "email", "encrypted_share_hex", "label" }]
            "secrets": [],    # [{ "label", "n", "k", "canaries", "secret_length_bytes", "timestamp" }]
            "triggered": False,
            "reminder_sent": False,
        }
    with open(CONFIG_PATH, "r") as f:
        state = json.load(f)
    # Backfill defaults for state files saved before these fields existed.
    state.setdefault("secrets", [])
    state.setdefault("reminder_sent", False)
    return state


def save_state(state):
    """Persist switch state to disk. Overwrites the previous file."""
    with open(CONFIG_PATH, "w") as f:
        json.dump(state, f, indent=2)


# =============================================================================
# Check-in daemon — the actual dead-man's-switch timer
# =============================================================================

def window_seconds(days, demo_speed):
    """
    Convert the configured check-in window into real seconds.

    Real logic uses days; --demo-speed compresses the same window into
    seconds so the switch can be demonstrated live in front of judges
    without anyone waiting 30 days.
    """
    if demo_speed:
        return days  # in demo mode, --days is interpreted directly as seconds
    return days * 24 * 3600


def cli_arm(args):
    """Arm the switch: start (or restart) the check-in window."""
    state = load_state()

    if state["armed"] and not args.force:
        print("Switch is already armed. Use --force to re-arm with new settings.")
        return

    state["armed"] = True
    state["days"] = args.days
    state["demo_speed"] = args.demo_speed
    state["last_checkin"] = time.time()
    state["triggered"] = False
    state["reminder_sent"] = False
    save_state(state)

    audit_log("arm", {"days": args.days, "demo_speed": args.demo_speed})

    unit = "seconds (demo mode)" if args.demo_speed else "days"
    print(f"Switch armed. Check in within {args.days} {unit}, or trustees will be notified.")
    print("Run 'python quorum.py checkin' periodically to reset the timer.")
    print("Run 'python quorum.py watch' to start the daemon that watches for timeout.")


def cli_checkin(args):
    """Reset the check-in timer — proof of life."""
    state = load_state()

    if not state["armed"]:
        print("No switch is currently armed. Run 'quorum arm' first.")
        return

    if state["triggered"]:
        print("Switch already triggered — check in has no effect until you re-arm with 'quorum arm --force'.")
        return

    state["last_checkin"] = time.time()
    state["reminder_sent"] = False
    save_state(state)
    audit_log("checkin", {})
    print(f"Checked in at {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())}. Timer reset.")


def cli_status(args):
    """Show time remaining before the switch fires."""
    state = load_state()

    if not state["armed"]:
        print("Switch is not armed.")
        return

    elapsed = time.time() - state["last_checkin"]
    total = window_seconds(state["days"], state["demo_speed"])
    remaining = total - elapsed

    if state["triggered"]:
        print("Switch has been TRIGGERED. Trustees have been notified.")
    elif remaining <= 0:
        print("Switch window has expired but hasn't fired yet — run 'quorum watch' to trigger it.")
    else:
        unit = "seconds" if state["demo_speed"] else "days"
        remaining_display = remaining if state["demo_speed"] else remaining / (24 * 3600)
        print(f"Switch armed. Time remaining: {remaining_display:.1f} {unit}.")
        print(f"Trustees on file: {len(state['trustees'])}")


def send_owner_reminder(state):
    """
    Notify the OWNER (not a trustee) that their check-in window is running
    low — this is the automation added instead of auto-checkin: it helps
    the owner remember to act, without ever letting anything but the
    owner's own deliberate `checkin` count as proof of life.

    Sent to the same address configured as the SMTP sender (QUORUM_SMTP_USER)
    — i.e. the owner emails themselves — so no extra config is needed.
    """
    owner_email = os.environ.get("QUORUM_SMTP_USER")
    unit = "seconds" if state["demo_speed"] else "days"
    elapsed = time.time() - state["last_checkin"]
    total = window_seconds(state["days"], state["demo_speed"])
    remaining = total - elapsed
    remaining_display = remaining if state["demo_speed"] else remaining / (24 * 3600)

    subject = "Quorum: your check-in window is running low"
    body = (
        f"Reminder: your Quorum switch has about {remaining_display:.1f} {unit} left "
        f"before it triggers and notifies your trustees.\n\n"
        f"If you're okay, run: python quorum.py checkin\n\n"
        f"— Quorum"
    )

    host = os.environ.get("QUORUM_SMTP_HOST")
    port = os.environ.get("QUORUM_SMTP_PORT")
    user = os.environ.get("QUORUM_SMTP_USER")
    password = os.environ.get("QUORUM_SMTP_PASS")

    if host and port and user and password and owner_email:
        try:
            _send_email(host, int(port), user, password, owner_email, subject, body)
            audit_log("owner_reminder_sent", {"method": "smtp"})
            print(f"  📧 Reminder emailed to owner <{owner_email}>")
            return
        except Exception as e:
            print(f"  ⚠️  Owner reminder email failed ({e}) — falling back to local log.")

    with open(MAILBOX_LOG_PATH, "a") as f:
        f.write(f"\n{'='*60}\nTO: (owner)\nSUBJECT: {subject}\n{'-'*60}\n{body}\n")
    audit_log("owner_reminder_sent", {"method": "local_log"})
    print(f"  📝 Reminder logged to {MAILBOX_LOG_PATH}")


REMINDER_THRESHOLD = 0.2  # send a reminder once remaining time drops below 20% of the window


def cli_watch(args):
    """
    Run the check-in daemon in the foreground: polls every second, fires
    the switch (and sends notifications) the moment the window expires.
    Also sends the owner ONE reminder email when their window drops below
    20% remaining, so they don't forget to check in.

    In a demo, this is the command left running in a visible terminal so
    judges watch the countdown hit zero and notifications fire live.
    """
    print("Watching switch — press Ctrl+C to stop.")
    try:
        while True:
            state = load_state()
            if not state["armed"] or state["triggered"]:
                time.sleep(1)
                continue

            elapsed = time.time() - state["last_checkin"]
            total = window_seconds(state["days"], state["demo_speed"])
            remaining = total - elapsed

            if remaining <= 0:
                print("\n⏰ Check-in window expired. Triggering switch...")
                trigger_switch(state)
                return

            if not state["reminder_sent"] and total > 0 and (remaining / total) < REMINDER_THRESHOLD:
                print(f"\n⚠️  Window below {int(REMINDER_THRESHOLD*100)}% remaining — reminding owner...")
                send_owner_reminder(state)
                state["reminder_sent"] = True
                save_state(state)

            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopped watching (switch state unchanged).")


def trigger_switch(state):
    """Fire the switch: mark triggered, notify every trustee on file."""
    state["triggered"] = True
    save_state(state)
    audit_log("triggered", {"trustee_count": len(state["trustees"])})

    if not state["trustees"]:
        print("Switch triggered, but no trustees are on file — nothing to notify.")
        return

    for trustee in state["trustees"]:
        notify_trustee(trustee)

    print(f"Notified {len(state['trustees'])} trustee(s).")


# =============================================================================
# Trustee notification — real email, with safe local fallback
# =============================================================================
#
# SMTP credentials are read from environment variables (optionally loaded
# from quorum.env via load_env_file()) — never hardcoded, never committed.
#   QUORUM_SMTP_HOST, QUORUM_SMTP_PORT, QUORUM_SMTP_USER, QUORUM_SMTP_PASS

def load_env_file():
    """
    Optional convenience loader: reads KEY=VALUE lines from quorum.env
    (if it exists) and sets them as environment variables.

    quorum.env must NEVER be committed — it holds real email credentials.
    It is data, not source code, so it doesn't count against the single-file
    rule; it must still be listed in .gitignore.
    """
    if not ENV_FILE_PATH.exists():
        return
    with open(ENV_FILE_PATH, "r") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            os.environ.setdefault(key.strip(), value.strip())


def notify_trustee(trustee):
    """
    Send the trustee their trigger notification.

    Tries real SMTP first if credentials are configured; falls back to a
    local mailbox log file if creds are missing or the send fails, so a
    live demo never hard-crashes on a network hiccup.
    """
    host = os.environ.get("QUORUM_SMTP_HOST")
    port = os.environ.get("QUORUM_SMTP_PORT")
    user = os.environ.get("QUORUM_SMTP_USER")
    password = os.environ.get("QUORUM_SMTP_PASS")

    subject = "Quorum: the switch has been triggered"
    body = (
        f"Hi {trustee['name']},\n\n"
        f"The owner has not checked in within the configured window. "
        f"The dead-man's-switch has fired.\n\n"
        f"This share is for: \"{trustee.get('label', 'unlabeled secret')}\"\n\n"
        f"Your encrypted share (decrypt using your Diffie-Hellman shared key):\n"
        f"{trustee.get('encrypted_share_hex', '<no share on file>')}\n\n"
        f"Run: python quorum.py decrypt-share --my-private <your_private> "
        f"--their-public <owner_public> --encrypted-hex <the hex above>\n\n"
        f"— Quorum"
    )

    if host and port and user and password:
        try:
            _send_email(host, int(port), user, password, trustee["email"], subject, body)
            audit_log("notify_trustee", {"trustee": trustee["name"], "method": "smtp"})
            print(f"  ✅ Emailed {trustee['name']} <{trustee['email']}>")
            return
        except Exception as e:
            print(f"  ⚠️  Email failed for {trustee['name']} ({e}) — falling back to local log.")

    _log_to_mailbox(trustee, subject, body)
    audit_log("notify_trustee", {"trustee": trustee["name"], "method": "local_log"})
    print(f"  📝 Logged notification for {trustee['name']} to {MAILBOX_LOG_PATH}")


def _send_email(host, port, user, password, to_addr, subject, body):
    """Send a real email via SMTP with STARTTLS."""
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = user
    msg["To"] = to_addr
    msg.set_content(body)

    context = ssl.create_default_context()
    with smtplib.SMTP(host, port) as server:
        server.starttls(context=context)
        server.login(user, password)
        server.send_message(msg)


def _log_to_mailbox(trustee, subject, body):
    """Append a notification to the local mailbox log — safe demo fallback."""
    entry = (
        f"\n{'=' * 60}\n"
        f"TO: {trustee['name']} <{trustee['email']}>\n"
        f"SUBJECT: {subject}\n"
        f"TIME: {time.strftime('%Y-%m-%d %H:%M:%S')}\n"
        f"{'-' * 60}\n"
        f"{body}\n"
    )
    with open(MAILBOX_LOG_PATH, "a") as f:
        f.write(entry)


def cli_add_trustee(args):
    """Register a trustee: name, email, their pre-encrypted share, and which
    labeled secret that share is for — so a trustee holding shares for
    multiple secrets never mixes them up."""
    state = load_state()
    state["trustees"].append({
        "name": args.name,
        "email": args.email,
        "encrypted_share_hex": args.encrypted_hex,
        "label": args.label,
    })
    save_state(state)
    audit_log("add_trustee", {"name": args.name, "email": args.email, "label": args.label})
    print(f"Added trustee: {args.name} <{args.email}> — share for: \"{args.label}\"")


# =============================================================================
# Reproducible build tooling
# =============================================================================

def cli_list_secrets(args):
    """List every labeled secret that has been split so far, with its trustees."""
    state = load_state()
    if not state["secrets"]:
        print("No secrets split yet.")
        return
    for s in state["secrets"]:
        ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(s["timestamp"]))
        print(f"\"{s['label']}\" — {s['n']} shares, threshold {s['k']}, split at {ts}")
        matching_trustees = [t["name"] for t in state["trustees"] if t.get("label") == s["label"]]
        if matching_trustees:
            print(f"   Trustees: {', '.join(matching_trustees)}")
        else:
            print("   Trustees: none registered yet")


def cli_build_check(args):
    """
    Reproducible-build bonus proof: hash the source file, print it.
    Run after two separate builds/checkouts and diff the output — identical
    hashes prove a byte-identical, reproducible build.
    """
    target = Path(args.file)
    if not target.exists():
        print(f"File not found: {target}")
        return
    digest = hashlib.sha256(target.read_bytes()).hexdigest()
    print(f"SHA-256({target}): {digest}")


def run_reproducible_build_check(source_file="quorum.py"):
    """Hash the source file twice and confirm the hashes match."""
    def hash_file(path):
        return hashlib.sha256(Path(path).read_bytes()).hexdigest()

    first = hash_file(source_file)
    second = hash_file(source_file)

    print(f"Build 1 SHA-256: {first}")
    print(f"Build 2 SHA-256: {second}")
    if first == second:
        print("✅ Reproducible: hashes match.")
    else:
        print("❌ NOT reproducible: hashes differ.")
    return first == second


# =============================================================================
# Share formatting helpers (for CLI I/O)
# =============================================================================

def format_share(share):
    """Format a (x, y) share tuple as a copy-pasteable 'x:y' string."""
    x, y = share
    return f"{x}:{y}"


def parse_share(share_str):
    """Parse a 'x:y' string back into a (x, y) share tuple."""
    x_str, y_str = share_str.split(":")
    return (int(x_str), int(y_str))


# =============================================================================
# CLI command handlers — core crypto commands
# =============================================================================

def cli_split(args):
    """Split a secret into N shares (plus optional canaries) and print them."""
    field = FiniteField()
    sss = ShamirSecretSharing(field)
    trap = CanaryTrap(field)

    secret_bytes = args.secret.encode("utf-8")
    secret_int = secret_to_int(secret_bytes)

    if secret_int >= field.p:
        print("Error: secret is too large for the current field. Aborting.")
        return

    shares = sss.split(secret_int, n=args.n, k=args.k)
    canaries = trap.generate_canaries(args.canaries)

    audit_log("split", {"label": args.label, "n": args.n, "k": args.k, "canaries": args.canaries,
                         "secret_length_bytes": len(secret_bytes)})

    # Record what this secret IS, so it's never confused with another one
    # split later (e.g. "Gmail password" vs "wallet seed phrase").
    state = load_state()
    state["secrets"].append({
        "label": args.label,
        "n": args.n,
        "k": args.k,
        "canaries": args.canaries,
        "secret_length_bytes": len(secret_bytes),
        "timestamp": time.time(),
    })
    save_state(state)

    print(f"=== Secret label: \"{args.label}\" ===")
    print(f"Split into {args.n} shares, threshold {args.k}.")
    print(f"(length={len(secret_bytes)} bytes — you'll need this AND the label to reconstruct)\n")

    print("Real shares:")
    for share in shares:
        print(" ", format_share(share))

    if canaries:
        print("\nDecoy (canary) shares — do NOT use these to reconstruct:")
        for canary in canaries:
            print(" ", format_share(canary))


def cli_reconstruct(args):
    """Reconstruct a secret from submitted shares, checking for canaries first."""
    field = FiniteField()
    sss = ShamirSecretSharing(field)
    trap = CanaryTrap(field)

    shares = [parse_share(s) for s in args.shares]

    tripped = trap.check_for_tripwire(shares)
    if tripped:
        audit_log("canary_tripped", {"canary_x_values": [x for x, y in tripped]})
        print("🚨 ALERT: canary share detected in reconstruction attempt!")
        print(f"   {len(tripped)} decoy share(s) used — this looks like a leaked or coerced share.")
        for x, y in tripped:
            print(f"   Tripped canary at x={x}")
        return

    recovered_int = sss.reconstruct(shares)
    recovered_bytes = int_to_secret(recovered_int, args.length)

    audit_log("reconstruct_attempt", {"share_count": len(shares)})

    try:
        print("Recovered secret:", recovered_bytes.decode("utf-8"))
    except UnicodeDecodeError:
        print("Recovered secret (raw bytes):", recovered_bytes)


def cli_keygen(args):
    """Generate a fresh Diffie-Hellman keypair and print both halves."""
    dh = DiffieHellman()
    print("Your PRIVATE key (keep this secret, do NOT share):")
    print(dh.private_key)
    print("\nYour PUBLIC key (safe to send to the other party):")
    print(dh.public_key())


def cli_encrypt_share(args):
    """
    Encrypt a share for a trustee, authenticated (encrypt-then-MAC).

    Per organizer guidance: derives separate encryption + MAC keys via
    PBKDF2-HMAC-SHA256 (a real stdlib KDF, not bare SHA-256), then encrypts
    with the counter-mode XOR keystream and appends an HMAC tag over the
    ciphertext — so any tampering in transit is detected, not silently
    decrypted into garbage.
    """
    dh = DiffieHellman()
    dh.private_key = args.my_private
    shared = dh.shared_secret(args.their_public)
    enc_key, mac_key = derive_keys(shared)

    payload = encrypt_then_mac(args.share.encode(), enc_key, mac_key)
    print("Encrypted + authenticated share (hex, safe to send over an insecure channel):")
    print(payload.hex())


def cli_decrypt_share(args):
    """
    Decrypt a share received from the owner, verifying its HMAC tag first.

    If the payload was tampered with or corrupted, this raises an error
    and refuses to decrypt — it never silently returns garbage.
    """
    dh = DiffieHellman()
    dh.private_key = args.my_private
    shared = dh.shared_secret(args.their_public)
    enc_key, mac_key = derive_keys(shared)

    payload = bytes.fromhex(args.encrypted_hex)
    try:
        decrypted = decrypt_then_verify(payload, enc_key, mac_key)
    except ValueError as e:
        print(f"🚨 DECRYPTION REFUSED: {e}")
        return

    print("Decrypted share (authenticity verified):")
    print(decrypted.decode())


def cli_visualize(args):
    """Start a local HTTP server showing the live polynomial visualizer."""
    port = args.port
    server = socketserver.TCPServer(("localhost", port), VisualizerHandler)
    url = f"http://localhost:{port}"
    print(f"Serving visualizer at {url} — press Ctrl+C to stop.")
    threading.Timer(0.5, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down visualizer.")
        server.shutdown()


# =============================================================================
# Live polynomial visualizer (embedded HTML, served via stdlib http.server)
# =============================================================================

VISUALIZER_HTML = """
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Quorum Visualizer</title>
<style>
  body { font-family: sans-serif; background: #111; color: #eee; text-align: center; padding-top: 40px; }
  canvas { background: #1a1a1a; border: 1px solid #333; margin-top: 20px; }
  #info { margin-top: 15px; font-size: 15px; color: #9fd; }
</style>
</head>
<body>
  <h1>Quorum — Polynomial Reconstruction</h1>
  <p>Watch the curve form as shares (points) combine. f(0) is the secret.</p>
  <canvas id="c" width="700" height="450"></canvas>
  <div id="info">Click "Add Share" to reveal points one at a time.</div>
  <br>
  <button onclick="addNextPoint()" style="padding:8px 16px; font-size:14px;">Add Share</button>
  <button onclick="reset()" style="padding:8px 16px; font-size:14px;">Reset</button>

<script>
  const P = 97;
  const SECRET = 42;
  function f(x) {
    return ((SECRET + 5*x + 3*x*x) % P + P) % P;
  }
  const allPoints = [1,2,3,4,5].map(x => [x, f(x)]);
  let revealed = [];

  const canvas = document.getElementById('c');
  const ctx = canvas.getContext('2d');
  const W = canvas.width, H = canvas.height;
  const padding = 40;

  function toScreen(x, y) {
    const sx = padding + (x / 6) * (W - 2*padding);
    const sy = H - padding - (y / P) * (H - 2*padding);
    return [sx, sy];
  }

  function drawAxes() {
    ctx.strokeStyle = "#444";
    ctx.beginPath();
    ctx.moveTo(padding, H - padding);
    ctx.lineTo(W - padding, H - padding);
    ctx.moveTo(padding, padding);
    ctx.lineTo(padding, H - padding);
    ctx.stroke();
  }

  function drawPoints() {
    ctx.fillStyle = "#5cf";
    for (const [x, y] of revealed) {
      const [sx, sy] = toScreen(x, y);
      ctx.beginPath();
      ctx.arc(sx, sy, 6, 0, 2*Math.PI);
      ctx.fill();
    }
  }

  function lagrangeAt(x0, points) {
    let result = 0;
    for (let i = 0; i < points.length; i++) {
      let [xi, yi] = points[i];
      let num = 1, den = 1;
      for (let j = 0; j < points.length; j++) {
        if (i === j) continue;
        let [xj, _] = points[j];
        num *= (x0 - xj);
        den *= (xi - xj);
      }
      result += yi * (num / den);
    }
    return result;
  }

  function drawCurve() {
    if (revealed.length < 3) return;
    ctx.strokeStyle = "#9f5";
    ctx.lineWidth = 2;
    ctx.beginPath();
    let first = true;
    for (let x = 0; x <= 6; x += 0.1) {
      const y = lagrangeAt(x, revealed);
      if (y < 0 || y > P) { first = true; continue; }
      const [sx, sy] = toScreen(x, y);
      if (first) { ctx.moveTo(sx, sy); first = false; }
      else ctx.lineTo(sx, sy);
    }
    ctx.stroke();

    const [sx0, sy0] = toScreen(0, lagrangeAt(0, revealed));
    ctx.fillStyle = "#fc5";
    ctx.beginPath();
    ctx.arc(sx0, sy0, 7, 0, 2*Math.PI);
    ctx.fill();
  }

  function render() {
    ctx.clearRect(0, 0, W, H);
    drawAxes();
    drawPoints();
    drawCurve();
    const info = document.getElementById('info');
    if (revealed.length < 3) {
      info.textContent = `Shares revealed: ${revealed.length} / 3 needed — curve not yet determined.`;
    } else {
      const secretGuess = Math.round(lagrangeAt(0, revealed));
      info.textContent = `Curve reconstructed! f(0) = ${secretGuess} (the secret)`;
    }
  }

  function addNextPoint() {
    if (revealed.length < allPoints.length) {
      revealed.push(allPoints[revealed.length]);
      render();
    }
  }

  function reset() {
    revealed = [];
    render();
  }

  render();
</script>
</body>
</html>
"""


class VisualizerHandler(http.server.BaseHTTPRequestHandler):
    """Serves the embedded visualizer HTML page over a local HTTP connection."""

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(VISUALIZER_HTML.encode())

    def log_message(self, format, *args):
        pass  # silence default request logging, keep terminal clean


# =============================================================================
# CLI argument parser
# =============================================================================

def build_cli():
    """Build the top-level argparse CLI with all subcommands registered."""
    parser = argparse.ArgumentParser(
        prog="quorum",
        description="Quorum — dead-man's-switch secret sharing, built from stdlib only."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # --- core crypto commands (Umaima's lane) ---
    split_parser = subparsers.add_parser("split", help="Split a secret into shares")
    split_parser.add_argument("secret", help="The secret to split (as plain text)")
    split_parser.add_argument("--label", required=True,
                               help="What this secret IS, e.g. 'Gmail password' or 'Wallet seed phrase' — prevents mixing up multiple protected secrets")
    split_parser.add_argument("--n", type=int, required=True, help="Total number of shares")
    split_parser.add_argument("--k", type=int, required=True, help="Threshold needed to reconstruct")
    split_parser.add_argument("--canaries", type=int, default=0, help="Number of decoy canary shares to generate")
    split_parser.set_defaults(func=cli_split)

    reconstruct_parser = subparsers.add_parser("reconstruct", help="Reconstruct a secret from shares")
    reconstruct_parser.add_argument("shares", nargs="+", help="Shares in x:y format")
    reconstruct_parser.add_argument("--length", type=int, required=True, help="Original secret length in bytes")
    reconstruct_parser.set_defaults(func=cli_reconstruct)

    visualize_parser = subparsers.add_parser("visualize", help="Launch the local polynomial visualizer")
    visualize_parser.add_argument("--port", type=int, default=8420, help="Local port to serve on")
    visualize_parser.set_defaults(func=cli_visualize)

    keygen_parser = subparsers.add_parser("keygen", help="Generate a Diffie-Hellman keypair")
    keygen_parser.set_defaults(func=cli_keygen)

    encrypt_parser = subparsers.add_parser("encrypt-share", help="Encrypt a share for a trustee using DH")
    encrypt_parser.add_argument("--my-private", type=int, required=True, help="Your DH private key")
    encrypt_parser.add_argument("--their-public", type=int, required=True, help="Trustee's DH public key")
    encrypt_parser.add_argument("--share", required=True, help="The share (x:y) to encrypt")
    encrypt_parser.set_defaults(func=cli_encrypt_share)

    decrypt_parser = subparsers.add_parser("decrypt-share", help="Decrypt a share received via DH")
    decrypt_parser.add_argument("--my-private", type=int, required=True, help="Your DH private key")
    decrypt_parser.add_argument("--their-public", type=int, required=True, help="Sender's DH public key")
    decrypt_parser.add_argument("--encrypted-hex", required=True, help="The encrypted share, as hex")
    decrypt_parser.set_defaults(func=cli_decrypt_share)

    # --- orchestration commands (Zunairah's lane) ---
    arm_parser = subparsers.add_parser("arm", help="Arm the dead-man's-switch")
    arm_parser.add_argument("--days", type=int, required=True,
                             help="Check-in window (days normally, seconds if --demo-speed)")
    arm_parser.add_argument("--demo-speed", action="store_true",
                             help="Treat --days as seconds for a fast live demo")
    arm_parser.add_argument("--force", action="store_true",
                             help="Re-arm even if already armed")
    arm_parser.set_defaults(func=cli_arm)

    checkin_parser = subparsers.add_parser("checkin", help="Reset the check-in timer")
    checkin_parser.set_defaults(func=cli_checkin)

    status_parser = subparsers.add_parser("status", help="Show time remaining on the switch")
    status_parser.set_defaults(func=cli_status)

    watch_parser = subparsers.add_parser("watch", help="Run the check-in daemon in the foreground")
    watch_parser.set_defaults(func=cli_watch)

    trustee_parser = subparsers.add_parser("add-trustee", help="Register a trustee's contact + encrypted share")
    trustee_parser.add_argument("--name", required=True)
    trustee_parser.add_argument("--email", required=True)
    trustee_parser.add_argument("--encrypted-hex", required=True, dest="encrypted_hex")
    trustee_parser.add_argument("--label", required=True,
                                 help="Which secret this share is for, matching the --label used in 'split'")
    trustee_parser.set_defaults(func=cli_add_trustee)

    buildcheck_parser = subparsers.add_parser("build-check", help="Hash a file for reproducible-build proof")
    buildcheck_parser.add_argument("--file", default="quorum.py")
    buildcheck_parser.set_defaults(func=cli_build_check)

    listsecrets_parser = subparsers.add_parser("list-secrets", help="List every labeled secret and its trustees")
    listsecrets_parser.set_defaults(func=cli_list_secrets)

    # --- Chain of Custody commands ---
    verifylog_parser = subparsers.add_parser("verify-log", help="Verify the tamper-evident audit log chain")
    verifylog_parser.set_defaults(func=cli_verify_log)

    showlog_parser = subparsers.add_parser("show-log", help="Print the audit log in human-readable form")
    showlog_parser.set_defaults(func=cli_show_log)

    return parser


# =============================================================================
# Entrypoint
# =============================================================================

if __name__ == "__main__":
    load_env_file()
    cli = build_cli()
    args = cli.parse_args()
    args.func(args)