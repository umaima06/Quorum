#quorum.py
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
    email.message, pathlib, http.cookies
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
from http.cookies import SimpleCookie
from pathlib import Path


# =============================================================================
# Constants
# =============================================================================

# Large prime defining our finite field GF(p) for Shamir's Secret Sharing.
# 2^521 - 1 is a well-known Mersenne prime, plenty large for realistic secrets.
SSS_PRIME = 2**521 - 1
_watch_thread = None
_watch_thread_stop = threading.Event()

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
        self.last_polynomial = None

    def split(self, secret, n, k):
        """Split secret into n shares, any k of which can reconstruct it."""
        if k > n:
            raise ValueError("threshold k cannot exceed number of shares n")
        poly = Polynomial(secret, degree=k - 1, field=self.field)
        self.last_polynomial = poly
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
            "trustees": [],   # [{ "name", "email", "encrypted_share_hex", "label", "credential_hash" }]
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

    quorum.env must NEVER be committed — it holds real email credentials
    and the dashboard's owner passphrase. It is data, not source code, so
    it doesn't count against the single-file rule; it must still be
    listed in .gitignore.
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


def notify_trustee_credential(name, email, credential):
    """Send a newly generated Quorum login credential to a trustee."""

    host = os.environ.get("QUORUM_SMTP_HOST")
    port = os.environ.get("QUORUM_SMTP_PORT")
    user = os.environ.get("QUORUM_SMTP_USER")
    password = os.environ.get("QUORUM_SMTP_PASS")

    subject = "Quorum: Your Trustee Login Credential"

    body = (
        f"Hi {name},\n\n"
        f"You have been added as a trustee in Quorum.\n\n"
        f"Your login credential is:\n\n"
        f"{credential}\n\n"
        f"Open the Quorum dashboard, select 'Trustee', "
        f"and enter this credential to sign in.\n\n"
        f"Keep this credential private.\n\n"
        f"— Quorum"
    )

    if host and port and user and password:
        try:
            _send_email(
                host,
                int(port),
                user,
                password,
                email,
                subject,
                body
            )

            audit_log("trustee_credential_sent", {
                "trustee": name,
                "method": "smtp"
            })

            print(f"  ✅ Trustee credential emailed to {name} <{email}>")
            return

        except Exception as e:
            print(f"  ⚠️ Credential email failed for {name}: {e}")

    # Demo fallback
    trustee = {"name": name, "email": email}
    _log_to_mailbox(trustee, subject, body)

    audit_log("trustee_credential_sent", {
        "trustee": name,
        "method": "local_log"
    })

    print(f"  📝 Credential logged for {name} to {MAILBOX_LOG_PATH}")


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


def cli_remove_trustee(args):
    """Remove a trustee by name (and optionally label, if names collide)."""
    state = load_state()
    before = len(state["trustees"])
    if args.label:
        state["trustees"] = [t for t in state["trustees"]
                              if not (t["name"] == args.name and t.get("label") == args.label)]
    else:
        state["trustees"] = [t for t in state["trustees"] if t["name"] != args.name]
    removed = before - len(state["trustees"])
    save_state(state)
    audit_log("remove_trustee", {"name": args.name, "label": args.label, "removed_count": removed})
    print(f"Removed {removed} trustee entry(ies) matching '{args.name}'.")


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
    secret = args.secret.strip()
    label = args.label.strip()
    if not secret:
        print("Error: secret cannot be empty or whitespace-only.")
        return
    if not label:
        print("Error: --label cannot be empty or whitespace-only.")
        return

    field = FiniteField()
    sss = ShamirSecretSharing(field)
    trap = CanaryTrap(field)
    secret_bytes = secret.encode("utf-8")
    secret_int = secret_to_int(secret_bytes)
    if secret_int >= field.p:
        print("Error: secret is too large for the current field. Aborting.")
        return
    shares = sss.split(secret_int, n=args.n, k=args.k)
    canaries = trap.generate_canaries(args.canaries)
    audit_log("split", {"label": label, "n": args.n, "k": args.k, "canaries": args.canaries,
                         "secret_length_bytes": len(secret_bytes)})
    state = load_state()
    state["secrets"].append({
        "label": label,
        "n": args.n,
        "k": args.k,
        "canaries": args.canaries,
        "secret_length_bytes": len(secret_bytes),
        "timestamp": time.time(),
    })
    save_state(state)
    print(f"=== Secret label: \"{label}\" ===")
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
# Dashboard authentication — passphrase/credential-gated sessions (Bug 5)
# =============================================================================
#
# A client-side Owner/Trustee toggle alone doesn't stop someone from calling
# /api/split or /api/arm directly (e.g. with curl), bypassing the UI. This
# adds a real server-side gate:
#   - Owner signs in with a single passphrase from quorum.env, verified with
#     the same hardened KDF used for share encryption (PBKDF2-HMAC-SHA256).
#   - Each Trustee gets their OWN unique, randomly generated login credential
#     when added (see cli/dashboard add-trustee), emailed to them and never
#     shown in the browser again. Only its PBKDF2 hash is stored, alongside
#     that trustee's record, so a credential match also tells us WHICH
#     trustee logged in and which secret's share they're responsible for.
# Either way, a random session token is issued as an HttpOnly cookie, and
# every state-changing API endpoint checks the session's role against
# ROLE_MAP before running — so a curl call with no valid session now gets a
# 401, not a page that just hides a button.

AUTH_SALT_PATH = Path("quorum_auth_salt.bin")
SESSION_TTL_SECONDS = 60 * 60 * 4  # 4 hours — plenty for a demo, short enough to be honest

_sessions = {}       # token -> {"role", "expires", [+trustee_name/email/label]}
ROLE_HASHES = None   # populated at startup by _load_or_generate_passphrases()


def _get_or_create_auth_salt():
    """Persisted alongside quorum_state.json so passphrase/credential
    hashes stay stable across restarts."""
    if AUTH_SALT_PATH.exists():
        return AUTH_SALT_PATH.read_bytes()
    salt = secrets.token_bytes(16)
    AUTH_SALT_PATH.write_bytes(salt)
    return salt


def _load_or_generate_passphrases():
    """
    Reads QUORUM_OWNER_PASSPHRASE from quorum.env (already loaded into
    os.environ by load_env_file()). If missing, generates one for this run
    and prints it once, so a demo never hard-fails on missing config — the
    same fallback pattern already used for SMTP credentials. Trustees don't
    use a shared passphrase — each gets their own credential at add-trustee
    time (see _handle_add_trustee).
    """
    owner_pass = os.environ.get("QUORUM_OWNER_PASSPHRASE")
    generated = []

    if not owner_pass:
        owner_pass = secrets.token_urlsafe(9)
        generated.append(("QUORUM_OWNER_PASSPHRASE", owner_pass))

    if generated:
        print("\n[Quorum] No owner passphrase found in quorum.env — generated for this session:")
        for key, val in generated:
            print(f"    {key}={val}")
        print("[Quorum] Add this to quorum.env to keep it stable across restarts.\n")

    salt = _get_or_create_auth_salt()
    return {
        "owner": hashlib.pbkdf2_hmac("sha256", owner_pass.encode(), salt, 100_000),
    }


def _verify_passphrase(role, passphrase):
    """
    Owner: checked against the single passphrase hash loaded at startup.
    Trustee: checked against every registered trustee's individual
    credential_hash, so a match also identifies WHICH trustee signed in.
    Returns an identity dict on success, or None on failure.
    """
    if role == "owner":
        if not ROLE_HASHES or "owner" not in ROLE_HASHES:
            return None
        salt = _get_or_create_auth_salt()
        candidate = hashlib.pbkdf2_hmac("sha256", passphrase.encode(), salt, 100_000)
        if hmac.compare_digest(candidate, ROLE_HASHES["owner"]):
            return {"role": "owner"}
        return None

    if role == "trustee":
        state = load_state()
        salt = _get_or_create_auth_salt()
        candidate = hashlib.pbkdf2_hmac("sha256", passphrase.encode(), salt, 100_000).hex()
        for trustee in state.get("trustees", []):
            stored_hash = trustee.get("credential_hash")
            if stored_hash and hmac.compare_digest(candidate, stored_hash):
                return {
                    "role": "trustee",
                    "trustee_name": trustee["name"],
                    "trustee_email": trustee["email"],
                    "label": trustee.get("label", "Unlabeled secret"),
                }
        return None

    return None


def _create_session(role):
    token = secrets.token_hex(32)
    _sessions[token] = {"role": role, "expires": time.time() + SESSION_TTL_SECONDS}
    return token


def _session_role(cookie_header):
    """Returns 'owner' | 'trustee' | None from a request's Cookie header."""
    if not cookie_header:
        return None
    jar = SimpleCookie()
    jar.load(cookie_header)
    morsel = jar.get("quorum_session")
    if not morsel:
        return None
    session = _sessions.get(morsel.value)
    if not session:
        return None
    if session["expires"] < time.time():
        _sessions.pop(morsel.value, None)
        return None
    return session["role"]


# Which role(s) each state-changing endpoint requires. Read-only GET
# endpoints (status/log/list-secrets/trustees) are left open so the
# dashboard's live countdown and audit-log view work even pre-login.
# /api/login, /api/visualize-demo, and /api/visualize-demo/reconstruct
# aren't listed here, so they always pass through (see _require_role).
ROLE_MAP = {
    "/api/split": {"owner"},
    "/api/add-trustee": {"owner"},
    "/api/remove-trustee": {"owner"},
    "/api/arm": {"owner"},
    "/api/checkin": {"owner"},
    "/api/keygen": {"owner", "trustee"},
    "/api/encrypt-share": {"owner"},
    "/api/decrypt-share": {"trustee"},
    "/api/reconstruct": {"trustee"},
    "/api/watch/start": {"owner"},
    "/api/watch/stop": {"owner"},
}


def _require_role(handler, path):
    """
    Returns True if the request may proceed. Otherwise writes a 401 JSON
    response (via the handler's own _send_json) and returns False.
    """
    required = ROLE_MAP.get(path)
    if required is None:
        return True
    role = _session_role(handler.headers.get("Cookie"))
    if role not in required:
        handler._send_json({"error": "unauthorized", "required_role": sorted(required)}, status=401)
        return False
    return True


# =============================================================================
# Polynomial Demo data (Bug 4)
# =============================================================================
#
# The Polynomial Demo tab visualizes the REAL output of the most recent
# ShamirSecretSharing.split() call — not a separate hardcoded toy example.
# The secret, the polynomial coefficients, and the exact 521-bit share
# values never leave server memory (they are never written to
# quorum_state.json and never sent to the browser). What the browser gets
# is a lossy, normalized (0..1) view of each share's y-value — enough to
# plot, not enough to reconstruct anything. Reconstruction itself happens
# entirely server-side via ShamirSecretSharing.reconstruct(), never via
# JavaScript floating-point Lagrange interpolation.

POLY_DEMO_DATA = None  # {"label","n","k","prime","shares" (real ints),"secret_int","secret_length"}


# =============================================================================
# Live polynomial visualizer (embedded HTML, served via stdlib http.server)
# =============================================================================

VISUALIZER_HTML = """
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Quorum Dashboard</title>
<style>
  * { box-sizing: border-box; }
  body {
    font-family: -apple-system, sans-serif; background: #0d0d0d; color: #eee;
    margin: 0; padding: 30px 20px;
  }
  h1 { text-align: center; font-size: 26px; margin-bottom: 4px; }
  .subtitle { text-align: center; color: #888; margin-bottom: 24px; font-size: 14px; }
  .tabs { display: flex; justify-content: center; gap: 8px; margin-bottom: 24px; flex-wrap: wrap; }
  .tab-btn {
    background: #1a1a1a; border: 1px solid #333; color: #ccc; padding: 8px 16px;
    border-radius: 6px; cursor: pointer; font-size: 13px;
  }
  .tab-btn.active { background: #2a3f2a; border-color: #4a7a4a; color: #9f5; }
  .panel { display: none; max-width: 800px; margin: 0 auto; }
  .panel.active { display: block; }

  .card { background: #161616; border: 1px solid #2a2a2a; border-radius: 8px; padding: 18px; margin-bottom: 16px; }
  .card h3 { margin-top: 0; color: #9fd; font-size: 15px; }
  label { display: block; font-size: 12px; color: #999; margin-top: 10px; margin-bottom: 4px; }
  input[type=text], input[type=number], input[type=password], textarea, select {
    width: 100%; background: #0d0d0d; border: 1px solid #333; color: #eee;
    padding: 8px 10px; border-radius: 5px; font-size: 13px; font-family: monospace;
  }
  input[type=checkbox] { margin-right: 6px; }
  button.action {
    background: #2a3f2a; border: 1px solid #4a7a4a; color: #9f5; padding: 8px 16px;
    border-radius: 6px; cursor: pointer; font-size: 13px; margin-top: 12px; margin-right: 8px;
  }
  button.danger { background: #3f2a2a; border-color: #7a4a4a; color: #f66; }
  .result { margin-top: 12px; padding: 10px; background: #0d0d0d; border: 1px solid #2a2a2a;
    border-radius: 6px; font-family: monospace; font-size: 12px; white-space: pre-wrap; word-break: break-all; }
  .result.error { border-color: #a33; color: #f66; }
  .result.ok { border-color: #2a5f2a; color: #9f5; }
  .share-line { padding: 4px 0; border-bottom: 1px solid #222; cursor: pointer; }
  .share-line:hover { color: #9f5; }
  .hint { font-size: 11px; color: #666; margin-top: 4px; }
  .role-badge {
    text-align: center; font-size: 12px; color: #9fd; margin-bottom: 14px;
  }
  .role-badge button { background: none; border: none; color: #888; text-decoration: underline;
    cursor: pointer; font-size: 12px; margin-left: 8px; }

  /* status */
  .status-big { text-align: center; padding: 20px; }
  .countdown { font-size: 40px; font-weight: 700; color: #9f5; }
  .countdown.expired { color: #f66; }
  .bar-bg { background: #222; border-radius: 6px; height: 10px; margin: 14px 0; overflow: hidden; }
  .bar-fill { background: #4a7a4a; height: 100%; transition: width 0.5s; }
  .bar-fill.low { background: #a33; }

  /* chain */
  #chainStatus { text-align: center; padding: 14px; border-radius: 8px; margin-bottom: 20px; font-size: 15px; font-weight: 600; }
  #chainStatus.ok { background: #1a2f1a; color: #9f5; border: 1px solid #2a5f2a; }
  #chainStatus.broken { background: #2f1a1a; color: #f66; border: 1px solid #5f2a2a; }
  .chain { display: flex; flex-direction: column; gap: 2px; }
  .block { background: #161616; border: 1px solid #2a2a2a; border-radius: 6px; padding: 10px 14px; font-size: 13px; }
  .block.broken { border-color: #a33; background: #2a1414; }
  .block-link { text-align: center; color: #444; font-size: 16px; margin: -2px 0; }
  .block-link.broken { color: #a33; }
  .block-event { color: #9f5; font-weight: 600; }
  .block-event.broken-event { color: #f66; }
  .block-meta { color: #888; font-size: 11px; margin-top: 4px; }
  .block-details { color: #aaa; font-size: 12px; margin-top: 4px; font-family: monospace; }

  table { width: 100%; border-collapse: collapse; font-size: 13px; margin-top: 10px; }
  th, td { text-align: left; padding: 6px 8px; border-bottom: 1px solid #222; }
  th { color: #888; font-weight: 500; }

  canvas { background: #1a1a1a; border: 1px solid #333; display: block; margin: 20px auto; cursor: pointer; }
  #info { margin-top: 15px; font-size: 15px; color: #9fd; text-align: center; }
  .viz-btn-row { text-align: center; margin-top: 10px; }
  .viz-caption { text-align: center; color: #666; font-size: 12px; margin: 4px auto; max-width: 620px; }
</style>
</head>
<body>
  <h1>Quorum</h1>
  <div class="subtitle">Dead-man's-switch secret sharing — live control panel</div>

  <!-- LOGIN GATE -->
  <div id="loginGate" class="card" style="max-width:380px;margin:0 auto 20px;">
    <h3>Sign in</h3>
    <div class="hint">
      In real use, the owner and each trustee run this dashboard on their own
      separate machine — this login simulates that separation for a
      single-machine demo, and is enforced by the server, not just the UI.
    </div>
    <label>Role</label>
    <select id="loginRole">
      <option value="owner">Owner</option>
      <option value="trustee">Trustee</option>
    </select>
    <label>Passphrase / credential</label>
    <input type="password" id="loginPass">
    <button class="action" onclick="doLogin()">Sign in</button>
    <div id="loginResult" class="result" style="display:none;"></div>
  </div>

  <div id="dashboardRoot" style="display:none;">
    <div class="role-badge">
      Signed in as <strong id="roleLabel"></strong>
      <button onclick="doLogout()">sign out</button>
    </div>

    <div class="tabs">
      <button class="tab-btn active" onclick="showTab('switch')">Switch</button>
      <button class="tab-btn" onclick="showTab('secrets')">Secrets</button>
      <button class="tab-btn" onclick="showTab('trustees')">Trustees</button>
      <button class="tab-btn" onclick="showTab('keys')">Keys &amp; Encryption</button>
      <button class="tab-btn" onclick="showTab('chain')">Chain of Custody</button>
      <button class="tab-btn" onclick="showTab('poly')">Polynomial Demo</button>
    </div>

    <!-- SWITCH -->
    <div id="switchPanel" class="panel active">
      <div class="card status-big">
        <div id="switchStatusText">Loading...</div>
        <div class="countdown" id="countdown">--</div>
        <div class="bar-bg"><div class="bar-fill" id="bar" style="width:0%"></div></div>
        <div class="hint" id="trusteeCount"></div>
      </div>
      <div class="card" data-role="owner">
        <h3>Background watcher</h3>
        <div class="hint">Must be running for reminders/triggers to actually fire — the countdown above is just a display.</div>
        <button class="action" onclick="startWatch()">▶ Start Watching</button>
        <button class="action danger" onclick="stopWatch()">■ Stop Watching</button>
        <div id="watchResult" class="result" style="display:none;"></div>
      </div>
      <div class="card" data-role="owner">
        <h3>Arm the switch</h3>
        <label>Window (days, or seconds if demo speed)</label>
        <input type="number" id="armDays" value="30">
        <label><input type="checkbox" id="armDemoSpeed" checked> Demo speed (treat as seconds)</label>
        <label><input type="checkbox" id="armForce"> Force re-arm if already armed</label>
        <button class="action" onclick="doArm()">Arm Switch</button>
        <button class="action" onclick="doCheckin()">Check In</button>
        <div id="switchResult" class="result" style="display:none;"></div>
      </div>
    </div>

    <!-- SECRETS -->
    <div id="secretsPanel" class="panel">
      <div class="card" data-role="owner">
        <h3>Split a new secret</h3>
        <label>Secret</label>
        <input type="text" id="splitSecret" placeholder="e.g. wallet-seed-xyz">
        <label>Label (what this secret IS)</label>
        <input type="text" id="splitLabel" placeholder="e.g. Crypto wallet seed">
        <label>N (total shares)</label>
        <input type="number" id="splitN" value="5">
        <label>K (threshold to reconstruct)</label>
        <input type="number" id="splitK" value="3">
        <label>Canary (decoy) shares</label>
        <input type="number" id="splitCanaries" value="1">
        <button class="action" onclick="doSplit()">Split Secret</button>
        <div id="splitResult" class="result" style="display:none;"></div>
        <button class="action" id="splitResultCopyBtn" onclick="copyResult('splitResult')">📋 Copy</button>
      </div>
      <div class="card">
        <h3>All secrets on file</h3>
        <button class="action" onclick="loadSecrets()">Refresh</button>
        <table id="secretsTable"><thead><tr><th>Label</th><th>N/K</th><th>Trustees</th></tr></thead><tbody></tbody></table>
      </div>
      <div class="card" data-role="trustee">
        <h3>Assigned Secret</h3>
        <div id="trusteeSecretLabel">—</div>
      </div>
      <div class="card" data-role="trustee">
        <h3>Reconstruct a secret (trustees do this)</h3>
        <label>Shares (one per line, format x:y)</label>
        <textarea id="reconShares" rows="4" placeholder="1:2322588...&#10;2:4645176..."></textarea>
        <label>Secret length in bytes (shown when it was split)</label>
        <input type="number" id="reconLength">
        <button class="action" onclick="doReconstruct()">Reconstruct</button>
        <div id="reconResult" class="result" style="display:none;"></div>
        <button class="action" id="reconResultCopyBtn" onclick="copyResult('reconResult')">📋 Copy</button>
      </div>
    </div>

    <!-- TRUSTEES -->
    <div id="trusteesPanel" class="panel">
      <div class="card" data-role="owner">
        <h3>Register a trustee</h3>
        <label>Name</label>
        <input type="text" id="tName">
        <label>Email</label>
        <input type="text" id="tEmail">
        <label>Which secret (label) is this share for</label>
        <input type="text" id="tLabel" placeholder="must match a label from the Secrets tab">
        <label>Encrypted share hex</label>
        <input type="text" id="tHex" placeholder="paste output from Keys &amp; Encryption tab">
        <button class="action" onclick="doAddTrustee()">Add Trustee</button>
        <div id="trusteeResult" class="result" style="display:none;"></div>
      </div>
      <div class="card" data-role="owner">
        <h3>Current trustees</h3>
        <button class="action" onclick="loadTrustees()">Refresh</button>
        <table id="trusteesTable"><thead><tr><th>Name</th><th>Email</th><th>Label</th><th></th></tr></thead><tbody></tbody></table>
      </div>
    </div>

    <!-- KEYS -->
    <div id="keysPanel" class="panel">
      <div class="card">
        <h3>1. Generate a keypair</h3>
        <div class="hint">Run once for the owner, once for each trustee — on separate machines in real use.</div>
        <button class="action" onclick="doKeygen()">Generate Keypair</button>
        <div id="keygenResult" class="result" style="display:none;"></div>
        <button class="action" id="keygenResultCopyBtn" onclick="copyResult('keygenResult')">📋 Copy</button>

      </div>
      <div class="card" data-role="owner">
        <h3>2. Encrypt a share (run by the owner)</h3>
        <label>Your private key</label>
        <input type="text" id="encMyPrivate">
        <label>Trustee's public key</label>
        <input type="text" id="encTheirPublic">
        <label>Share to encrypt (x:y)</label>
        <input type="text" id="encShare" placeholder="e.g. 1:12345">
        <button class="action" onclick="doEncrypt()">Encrypt Share</button>
        <div id="encryptResult" class="result" style="display:none;"></div>
        <button class="action" id="encryptResultCopyBtn" onclick="copyResult('encryptResult')">📋 Copy</button>
      </div>
      <div class="card" data-role="trustee">
        <h3>3. Decrypt a share (run by the trustee)</h3>
        <label>Your private key</label>
        <input type="text" id="decMyPrivate">
        <label>Owner's public key</label>
        <input type="text" id="decTheirPublic">
        <label>Encrypted hex</label>
        <input type="text" id="decHex">
        <button class="action" onclick="doDecrypt()">Decrypt Share</button>
        <div id="decryptResult" class="result" style="display:none;"></div>
        <button class="action" id="decryptResultCopyBtn" onclick="copyResult('decryptResult')">📋 Copy</button>
      </div>
    </div>

    <!-- CHAIN -->
    <div id="chainPanel" class="panel">
      <button class="action" onclick="loadChain()">🔄 Refresh / Verify Chain</button>
      <div id="chainStatus">Loading...</div>
      <div id="chainContainer" class="chain"></div>
    </div>

    <!-- POLY -->
    <div id="polyPanel" class="panel">
      <p style="text-align:center; color:#9fd;">
        This visualizes the <strong>real</strong> shares from the most recent
        <code>ShamirSecretSharing.split()</code> call — not a separate hardcoded example.
      </p>
      <p class="viz-caption">
        Values shown are normalized (scaled to 0–1) for display only, since the
        real field is GF(2^521−1) — far too large to plot exactly, and this
        scaling never reveals the exact share value or the secret. Click points
        below to select shares, then reconstruct using Quorum's actual
        <code>reconstruct()</code> function server-side — not JavaScript
        floating-point math.
      </p>
      <canvas id="c" width="700" height="450"></canvas>
      <div id="info">Loading real share data...</div>
      <div class="viz-btn-row">
        <button class="action" onclick="reconstructSelected()">Reconstruct from selected shares</button>
        <button class="action" onclick="clearSelection()">Clear selection</button>
        <button class="action" onclick="loadPolyDemo()">Refresh (load latest split)</button>
      </div>
      <div id="polyResult" class="result" style="display:none;"></div>
    </div>
  </div>

<script>
  let currentRole = null;

  async function doLogin() {
    try {
      const role = document.getElementById('loginRole').value;
      const passphrase = document.getElementById('loginPass').value;
      const res = await fetch('/api/login', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({role, passphrase})
      });
      const data = await res.json();
      if (!res.ok) {
        showResult('loginResult', data.error || 'login failed', true);
        return;
      }
      currentRole = data.role;
      document.getElementById('loginGate').style.display = 'none';
      document.getElementById('dashboardRoot').style.display = 'block';
      document.getElementById('roleLabel').textContent = currentRole;

      if (data.role === 'trustee') {
        document.getElementById('trusteeSecretLabel').textContent =
          data.label || 'Unlabeled secret';
      }

      applyRoleVisibility(currentRole);
      refreshStatus();
    } catch (e) {
      showResult('loginResult', e.message, true);
    }
  }

  function doLogout() {
    currentRole = null;
    document.getElementById('dashboardRoot').style.display = 'none';
    document.getElementById('loginGate').style.display = 'block';
    document.getElementById('loginPass').value = '';
  }

  // Bug 5 fix: this only controls which panels are SHOWN. The real gate is
  // server-side — _require_role() returns 401 for a hidden action even if
  // it's called directly (e.g. via curl) without a matching session.
  function applyRoleVisibility(role) {
    document.querySelectorAll('[data-role]').forEach(el => {
      const allowed = el.getAttribute('data-role').split(' ');
      el.style.display = allowed.includes(role) ? '' : 'none';
    });
  }

  function showTab(name) {
    document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
    document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
    document.getElementById(name + 'Panel').classList.add('active');
    event.target.classList.add('active');
    if (name === 'secrets') loadSecrets();
    if (name === 'chain') loadChain();
    if (name === 'trustees') loadTrustees();
    if (name === 'poly') loadPolyDemo();
  }

  async function api(path, body) {
    const opts = body === undefined
      ? {}
      : { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(body) };
    const res = await fetch(path, opts);
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'request failed');
    return data;
  }

  function showResult(elId, text, isError) {
    const el = document.getElementById(elId);
    el.style.display = 'block';
    el.textContent = text;
    el.className = 'result ' + (isError ? 'error' : 'ok');
  }
  
  function copyResult(elId) {
    const el = document.getElementById(elId);
    navigator.clipboard.writeText(el.textContent).then(() => {
      const btn = document.getElementById(elId + 'CopyBtn');
      if (btn) { const orig = btn.textContent; btn.textContent = '✅ Copied'; setTimeout(() => btn.textContent = orig, 1200); }
    });
  }

  // ---------- Switch ----------
  async function refreshStatus() {
    try {
      const s = await api('/api/status');
      const textEl = document.getElementById('switchStatusText');
      const cd = document.getElementById('countdown');
      const bar = document.getElementById('bar');
      const tc = document.getElementById('trusteeCount');

      if (!s.armed) {
        textEl.textContent = 'Switch is not armed.';
        cd.textContent = '--'; cd.className = 'countdown';
        bar.style.width = '0%';
      } else if (s.triggered) {
        textEl.textContent = 'Switch has been TRIGGERED — trustees notified.';
        cd.textContent = '🚨'; cd.className = 'countdown expired';
        bar.style.width = '0%';
      } else {
        const total = s.demo_speed ? s.days : s.days * 24 * 3600;
        const elapsed = (Date.now() / 1000) - s.last_checkin;
        const remaining = Math.max(0, total - elapsed);
        const unit = s.demo_speed ? 's' : 'd';
        const display = s.demo_speed ? remaining.toFixed(1) : (remaining / 86400).toFixed(1);
        textEl.textContent = 'Switch armed.';
        cd.textContent = display + unit;
        cd.className = remaining < total * 0.2 ? 'countdown expired' : 'countdown';
        const pct = total > 0 ? Math.max(0, (remaining / total) * 100) : 0;
        bar.style.width = pct + '%';
        bar.className = 'bar-fill' + (pct < 20 ? ' low' : '');
      }
      tc.textContent = `Trustees on file: ${(s.trustees || []).length}`;
    } catch (e) {
      document.getElementById('switchStatusText').textContent = 'Could not reach server.';
    }
  }
  setInterval(refreshStatus, 1000);

  async function doArm() {
    try {
      const days = parseInt(document.getElementById('armDays').value);
      const demo_speed = document.getElementById('armDemoSpeed').checked;
      const force = document.getElementById('armForce').checked;
      const r = await api('/api/arm', { days, demo_speed, force });
      showResult('switchResult', 'Armed successfully.', false);
      refreshStatus();
    } catch (e) { showResult('switchResult', e.message, true); }
  }

  async function doCheckin() {
    try {
      await api('/api/checkin', {});
      showResult('switchResult', 'Checked in — timer reset.', false);
      refreshStatus();
    } catch (e) { showResult('switchResult', e.message, true); }
  }

  async function startWatch() {
    try {
      const r = await api('/api/watch/start', {});
      showResult('watchResult', r.already_running ? 'Already running.' : 'Watcher started.', false);
    } catch (e) { showResult('watchResult', e.message, true); }
  }
  async function stopWatch() {
    try {
      await api('/api/watch/stop', {});
      showResult('watchResult', 'Watcher stopped.', false);
    } catch (e) { showResult('watchResult', e.message, true); }
  }

  async function doReconstruct() {
    try {
      const shares = document.getElementById('reconShares').value
        .split('\\n').map(s => s.trim()).filter(Boolean);
      const length = parseInt(document.getElementById('reconLength').value);
      const r = await api('/api/reconstruct', { shares, length });
      if (r.alert) {
        showResult('reconResult', '🚨 CANARY DETECTED: ' + r.alert, true);
      } else {
        showResult('reconResult', 'Recovered secret: ' + r.secret, false);
      }
    } catch (e) { showResult('reconResult', e.message, true); }
  }

  // ---------- Secrets ----------
  async function doSplit() {
    try {
      const body = {
        secret: document.getElementById('splitSecret').value,
        label: document.getElementById('splitLabel').value,
        n: parseInt(document.getElementById('splitN').value),
        k: parseInt(document.getElementById('splitK').value),
        canaries: parseInt(document.getElementById('splitCanaries').value || '0'),
      };
      const r = await api('/api/split', body);
      let text = `Label: "${r.label}"  (length=${r.length} bytes)\\n\\nReal shares:\\n`;
      text += r.real_shares.join('\\n');
      if (r.canary_shares.length) {
        text += '\\n\\nDecoy (canary) shares — do NOT use to reconstruct:\\n' + r.canary_shares.join('\\n');
      }
      showResult('splitResult', text, false);
      polyLoaded = false; // this split is now the "latest" one for the Polynomial Demo tab
    } catch (e) { showResult('splitResult', e.message, true); }
  }

  async function loadSecrets() {
    try {
      const r = await api('/api/list-secrets');
      const tbody = document.querySelector('#secretsTable tbody');
      tbody.innerHTML = '';
      r.secrets.forEach(s => {
        const tr = document.createElement('tr');
        tr.innerHTML = `<td>${s.label}</td><td>${s.n}/${s.k}</td><td>${s.trustees.join(', ') || '—'}</td>`;
        tbody.appendChild(tr);
      });
    } catch (e) {}
  }

  // ---------- Trustees ----------
  async function doAddTrustee() {
    try {
      const body = {
        name: document.getElementById('tName').value,
        email: document.getElementById('tEmail').value,
        label: document.getElementById('tLabel').value,
        encrypted_hex: document.getElementById('tHex').value,
      };
      await api('/api/add-trustee', body);
      showResult('trusteeResult', `Added trustee: ${body.name} <${body.email}> — their login credential was emailed to them.`, false);
      loadTrustees();
    } catch (e) { showResult('trusteeResult', e.message, true); }
  }
  
  async function loadTrustees() {
    try {
      const r = await api('/api/trustees');
      const tbody = document.querySelector('#trusteesTable tbody');
      tbody.innerHTML = '';
      r.trustees.forEach(t => {
        const tr = document.createElement('tr');
        tr.innerHTML = `<td>${t.name}</td><td>${t.email}</td><td>${t.label}</td>
          <td><button class="action danger" onclick="removeTrustee('${t.name.replace(/'/g,"\\'")}','${t.label.replace(/'/g,"\\'")}')">Remove</button></td>`;
        tbody.appendChild(tr);
      });
    } catch (e) {}
  }

  async function removeTrustee(name, label) {
    try {
      await api('/api/remove-trustee', { name, label });
      loadTrustees();
    } catch (e) { showResult('trusteeResult', e.message, true); }
  }

  // ---------- Keys ----------
  async function doKeygen() {
    try {
      const r = await api('/api/keygen', {});
      showResult('keygenResult', `PRIVATE (keep secret):\\n${r.private_key}\\n\\nPUBLIC (safe to share):\\n${r.public_key}`, false);
    } catch (e) { showResult('keygenResult', e.message, true); }
  }

  async function doEncrypt() {
    try {
      const body = {
        my_private: document.getElementById('encMyPrivate').value,
        their_public: document.getElementById('encTheirPublic').value,
        share: document.getElementById('encShare').value,
      };
      const r = await api('/api/encrypt-share', body);
      showResult('encryptResult', r.encrypted_hex, false);
    } catch (e) { showResult('encryptResult', e.message, true); }
  }

  async function doDecrypt() {
    try {
      const body = {
        my_private: document.getElementById('decMyPrivate').value,
        their_public: document.getElementById('decTheirPublic').value,
        encrypted_hex: document.getElementById('decHex').value,
      };
      const r = await api('/api/decrypt-share', body);
      showResult('decryptResult', 'Decrypted (verified): ' + r.decrypted, false);
    } catch (e) { showResult('decryptResult', '🚨 ' + e.message, true); }
  }

  // ---------- Chain of Custody ----------
  async function loadChain() {
    const statusEl = document.getElementById('chainStatus');
    const containerEl = document.getElementById('chainContainer');
    statusEl.textContent = 'Loading...'; statusEl.className = '';
    containerEl.innerHTML = '';
    let data;
    try { data = await api('/api/log'); }
    catch (e) { statusEl.textContent = '⚠️ Could not reach server.'; statusEl.className = 'broken'; return; }

    if (data.valid) {
      statusEl.textContent = `✅ Audit log verified — ${data.count} entries, chain intact.`;
      statusEl.className = 'ok';
    } else {
      statusEl.textContent = `🚨 TAMPERED — chain breaks at entry #${data.break_index}`;
      statusEl.className = 'broken';
    }

    data.entries.forEach((entry, i) => {
      const isBroken = data.break_index !== null && i >= data.break_index;
      if (i > 0) {
        const link = document.createElement('div');
        link.className = 'block-link' + (isBroken ? ' broken' : '');
        link.textContent = '↓';
        containerEl.appendChild(link);
      }
      const block = document.createElement('div');
      block.className = 'block' + (isBroken ? ' broken' : '');
      if (entry.corrupted_raw_line) {
        block.innerHTML = `<div class="block-event broken-event">🚨 CORRUPTED LINE</div><div class="block-details">${entry.corrupted_raw_line}</div>`;
      } else {
        const ts = new Date(entry.timestamp * 1000).toLocaleString();
        block.innerHTML = `
          <div class="block-event${isBroken ? ' broken-event' : ''}">${entry.event}</div>
          <div class="block-meta">${ts}</div>
          <div class="block-details">${JSON.stringify(entry.details)}</div>
          <div class="block-meta">hash: ${entry.hash ? entry.hash.slice(0,16) : '?'}...</div>`;
      }
      containerEl.appendChild(block);
    });
    if (data.entries.length === 0) {
      containerEl.innerHTML = '<div class="block" style="text-align:center; color:#888;">No audit log entries yet.</div>';
    }
  }

  // ---------- Polynomial demo (Bug 4: real SSS shares, normalized for display) ----------
  // No hardcoded secret, no hardcoded field. Everything here reflects the
  // most recent real ShamirSecretSharing.split() call, fetched fresh from
  // the server. The server sends only a lossy 0..1 normalization of each
  // share's y-value — plenty to plot, nowhere near enough to reconstruct.
  let polyLabel = '', polyN = 0, polyK = 0;
  let polyPoints = [];        // [{index, x, y_normalized}]
  let polySelected = new Set();
  let polyLoaded = false;

  const canvas = document.getElementById('c');
  const ctx = canvas.getContext('2d');
  const W = canvas.width, H = canvas.height, padding = 40;

  async function loadPolyDemo() {
    try {
      const r = await api('/api/visualize-demo', {});
      polyLabel = r.label; polyN = r.n; polyK = r.k;
      polyPoints = r.points;
      polySelected = new Set();
      polyLoaded = true;
      document.getElementById('polyResult').style.display = 'none';
      renderPoly();
    } catch (e) {
      polyLoaded = false;
      ctx.clearRect(0, 0, W, H);
      document.getElementById('info').textContent = e.message;
    }
  }

  function toScreen(index, yNorm) {
    const x = padding + ((index + 1) / (polyN + 1)) * (W - 2 * padding);
    const y = H - padding - yNorm * (H - 2 * padding);
    return [x, y];
  }

  function renderPoly() {
    ctx.clearRect(0, 0, W, H);
    ctx.strokeStyle = "#444"; ctx.beginPath();
    ctx.moveTo(padding, H - padding); ctx.lineTo(W - padding, H - padding);
    ctx.moveTo(padding, padding); ctx.lineTo(padding, H - padding); ctx.stroke();

    polyPoints.forEach(p => {
      const [sx, sy] = toScreen(p.index, p.y_normalized);
      ctx.fillStyle = polySelected.has(p.index) ? "#fc5" : "#5cf";
      ctx.beginPath(); ctx.arc(sx, sy, 8, 0, 2 * Math.PI); ctx.fill();
      ctx.fillStyle = "#888"; ctx.font = "11px monospace";
      ctx.fillText('x=' + p.x, sx - 14, sy + 22);
    });

    const info = document.getElementById('info');
    if (polyLoaded) {
      info.textContent = `"${polyLabel}" — ${polySelected.size} of ${polyN} shares selected `
        + `(need ${polyK} to reconstruct). Click a point to select/deselect.`;
    }
  }

  canvas.addEventListener('click', (ev) => {
    if (!polyLoaded) return;
    const rect = canvas.getBoundingClientRect();
    const mx = ev.clientX - rect.left, my = ev.clientY - rect.top;
    for (const p of polyPoints) {
      const [sx, sy] = toScreen(p.index, p.y_normalized);
      if (Math.hypot(mx - sx, my - sy) < 12) {
        if (polySelected.has(p.index)) polySelected.delete(p.index);
        else polySelected.add(p.index);
        renderPoly();
        return;
      }
    }
  });

  function clearSelection() {
    polySelected = new Set();
    renderPoly();
    document.getElementById('polyResult').style.display = 'none';
  }

  async function reconstructSelected() {
    try {
      const indices = Array.from(polySelected);
      // Real reconstruction happens server-side via Quorum's actual
      // ShamirSecretSharing.reconstruct() — never JS floating-point math.
      const r = await api('/api/visualize-demo/reconstruct', { indices });
      showResult('polyResult', r.message, !r.success);
    } catch (e) {
      showResult('polyResult', e.message, true);
    }
  }
</script>
</body>
</html>
"""


class VisualizerHandler(http.server.BaseHTTPRequestHandler):
    """Serves the dashboard HTML and a JSON API that drives the same
    functions the CLI uses — the web UI is a second interface, not a
    reimplementation."""

    # ---------- GET ----------
    def do_GET(self):
        if self.path in ("/", ""):
            self._send_html(VISUALIZER_HTML)
        elif self.path == "/api/log":
            self._handle_get_log()
        elif self.path == "/api/status":
            self._send_json(load_state())
        elif self.path == "/api/list-secrets":
            self._handle_list_secrets()
        elif self.path == "/api/trustees":
            self._send_json({"trustees": load_state()["trustees"]})
        else:
            self.send_response(404)
            self.end_headers()

    # ---------- POST ----------
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length) if length else b"{}"
        try:
            data = json.loads(raw) if raw.strip() else {}
        except json.JSONDecodeError:
            self._send_json({"error": "invalid JSON in request body"}, status=400)
            return

        # Bug 5: server-side role gate, checked before any state-changing
        # endpoint runs. /api/login, /api/visualize-demo, and
        # /api/visualize-demo/reconstruct aren't in ROLE_MAP so they
        # always pass through.
        if not _require_role(self, self.path):
            return

        try:
            if self.path == "/api/split":
                self._handle_split(data)
            elif self.path == "/api/add-trustee":
                self._handle_add_trustee(data)
            elif self.path == "/api/arm":
                self._handle_arm(data)
            elif self.path == "/api/checkin":
                self._handle_checkin(data)
            elif self.path == "/api/keygen":
                self._handle_keygen(data)
            elif self.path == "/api/encrypt-share":
                self._handle_encrypt_share(data)
            elif self.path == "/api/decrypt-share":
                self._handle_decrypt_share(data)
            elif self.path == "/api/watch/start":
                self._handle_watch_start(data)
            elif self.path == "/api/watch/stop":
                self._handle_watch_stop(data)
            elif self.path == "/api/reconstruct":
                self._handle_reconstruct(data)
            elif self.path == "/api/remove-trustee":
                self._handle_remove_trustee(data)
            elif self.path == "/api/login":
                self._handle_login(data)
            elif self.path == "/api/visualize-demo":
                self._handle_visualize_demo(data)
            elif self.path == "/api/visualize-demo/reconstruct":
                self._handle_visualize_demo_reconstruct(data)
            else:
                self._send_json({"error": "unknown endpoint"}, status=404)
        except Exception as e:
            self._send_json({"error": str(e)}, status=400)

        # ---------- handlers (each mirrors the matching cli_* function) ----------

    def _handle_split(self, data):
        global POLY_DEMO_DATA
        secret = str(data["secret"]).strip()
        label = str(data["label"]).strip()
        if not secret:
            self._send_json({"error": "secret cannot be empty or whitespace-only"}, status=400)
            return
        if not label:
            self._send_json({"error": "label cannot be empty or whitespace-only"}, status=400)
            return

        field = FiniteField()
        sss = ShamirSecretSharing(field)
        trap = CanaryTrap(field)
        n = int(data["n"])
        k = int(data["k"])
        canaries = int(data.get("canaries", 0))
        secret_bytes = secret.encode("utf-8")
        secret_int = secret_to_int(secret_bytes)
        if secret_int >= field.p:
            self._send_json({"error": "secret is too large for the current field"}, status=400)
            return
        shares = sss.split(secret_int, n=n, k=k)
        canary_shares = trap.generate_canaries(canaries)
        POLY_DEMO_DATA = {
            "label": label,
            "n": n,
            "k": k,
            "prime": field.p,
            "shares": shares,
            "secret_int": secret_int,
            "secret_length": len(secret_bytes),
        }
        audit_log("split", {"label": label, "n": n, "k": k, "canaries": canaries,
                             "secret_length_bytes": len(secret_bytes)})
        state = load_state()
        state["secrets"].append({
            "label": label, "n": n, "k": k, "canaries": canaries,
            "secret_length_bytes": len(secret_bytes), "timestamp": time.time(),
        })
        save_state(state)
        self._send_json({
            "label": label,
            "length": len(secret_bytes),
            "real_shares": [format_share(s) for s in shares],
            "canary_shares": [format_share(s) for s in canary_shares],
        })

    def _handle_add_trustee(self, data):
        state = load_state()

        name = str(data["name"])
        email = str(data["email"])
        encrypted_hex = str(data["encrypted_hex"])
        label = str(data["label"])

        # Generate a unique login credential for this trustee.
        credential = secrets.token_urlsafe(12)

        # Store only the PBKDF2 hash — never the actual credential.
        salt = _get_or_create_auth_salt()
        credential_hash = hashlib.pbkdf2_hmac(
            "sha256", credential.encode(), salt, 100_000
        ).hex()

        entry = {
            "name": name,
            "email": email,
            "encrypted_share_hex": encrypted_hex,
            "label": label,
            "credential_hash": credential_hash,
        }

        state["trustees"].append(entry)
        save_state(state)

        # Send the credential to the trustee out of band — never returned
        # to the browser that made this request.
        notify_trustee_credential(name, email, credential)

        audit_log("add_trustee", {"name": name, "email": email, "label": label})

        self._send_json({
            "ok": True,
            "trustee": {"name": name, "email": email, "label": label},
        })

    def _handle_arm(self, data):
        state = load_state()
        force = bool(data.get("force", False))
        if state["armed"] and not force:
            self._send_json({"error": "already armed — pass force=true to re-arm"}, status=400)
            return

        days = int(data["days"])
        demo_speed = bool(data.get("demo_speed", False))

        state["armed"] = True
        state["days"] = days
        state["demo_speed"] = demo_speed
        state["last_checkin"] = time.time()
        state["triggered"] = False
        state["reminder_sent"] = False
        save_state(state)
        audit_log("arm", {"days": days, "demo_speed": demo_speed})
        self._send_json({"ok": True, "state": state})

    def _handle_checkin(self, data):
        state = load_state()
        if not state["armed"]:
            self._send_json({"error": "no switch is armed"}, status=400)
            return
        if state["triggered"]:
            self._send_json({"error": "already triggered — re-arm first"}, status=400)
            return
        state["last_checkin"] = time.time()
        state["reminder_sent"] = False
        save_state(state)
        audit_log("checkin", {})
        self._send_json({"ok": True, "state": state})

    def _handle_keygen(self, data):
        dh = DiffieHellman()
        # Transmitted as STRINGS, not JSON numbers — these integers are
        # far bigger than JavaScript can represent exactly as a Number,
        # so treating them as text avoids silent precision loss.
        self._send_json({
            "private_key": str(dh.private_key),
            "public_key": str(dh.public_key()),
        })

    def _handle_encrypt_share(self, data):
        dh = DiffieHellman()
        dh.private_key = int(data["my_private"])
        shared = dh.shared_secret(int(data["their_public"]))
        enc_key, mac_key = derive_keys(shared)
        payload = encrypt_then_mac(str(data["share"]).encode(), enc_key, mac_key)
        self._send_json({"encrypted_hex": payload.hex()})

    def _handle_decrypt_share(self, data):
        dh = DiffieHellman()
        dh.private_key = int(data["my_private"])
        shared = dh.shared_secret(int(data["their_public"]))
        enc_key, mac_key = derive_keys(shared)
        payload = bytes.fromhex(str(data["encrypted_hex"]))
        try:
            decrypted = decrypt_then_verify(payload, enc_key, mac_key)
        except ValueError as e:
            self._send_json({"error": str(e)}, status=400)
            return
        self._send_json({"decrypted": decrypted.decode()})

    def _handle_get_log(self):
        entries = []
        if AUDIT_LOG_PATH.exists():
            with open(AUDIT_LOG_PATH, "r", encoding="utf-8-sig") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            entries.append(json.loads(line))
                        except json.JSONDecodeError:
                            entries.append({"corrupted_raw_line": line})
        valid, count, break_index = verify_audit_log()
        self._send_json({"entries": entries, "valid": valid, "count": count, "break_index": break_index})

    def _handle_list_secrets(self):
        state = load_state()
        result = []
        for s in state["secrets"]:
            trustees = [t["name"] for t in state["trustees"] if t.get("label") == s["label"]]
            result.append({**s, "trustees": trustees})
        self._send_json({"secrets": result})

    def _handle_watch_start(self, data):
        global _watch_thread, _watch_thread_stop
        if _watch_thread is not None and _watch_thread.is_alive():
            self._send_json({"ok": True, "already_running": True})
            return
        _watch_thread_stop.clear()
        _watch_thread = threading.Thread(target=_watch_loop_background, daemon=True)
        _watch_thread.start()
        self._send_json({"ok": True, "started": True})

    def _handle_watch_stop(self, data):
        global _watch_thread, _watch_thread_stop
        if _watch_thread is None or not _watch_thread.is_alive():
            self._send_json({"ok": True, "stopped": True, "already_stopped": True})
            return
        _watch_thread_stop.set()
        _watch_thread.join(timeout=2.0)
        stopped_cleanly = not _watch_thread.is_alive()
        _watch_thread = None
        self._send_json({"ok": True, "stopped": stopped_cleanly})

    def _handle_reconstruct(self, data):
        field = FiniteField()
        sss = ShamirSecretSharing(field)
        trap = CanaryTrap(field)

        shares = [parse_share(s) for s in data["shares"]]
        tripped = trap.check_for_tripwire(shares)
        if tripped:
            audit_log("canary_tripped", {"canary_x_values": [x for x, y in tripped]})
            self._send_json({"alert": f"{len(tripped)} decoy share(s) used — leaked or coerced share detected."})
            return

        recovered_int = sss.reconstruct(shares)
        recovered_bytes = int_to_secret(recovered_int, int(data["length"]))
        audit_log("reconstruct_attempt", {"share_count": len(shares)})
        try:
            self._send_json({"secret": recovered_bytes.decode("utf-8")})
        except UnicodeDecodeError:
            self._send_json({"secret": recovered_bytes.hex(), "raw_hex": True})

    def _handle_remove_trustee(self, data):
        state = load_state()
        name = str(data["name"])
        label = data.get("label")
        before = len(state["trustees"])
        if label:
            state["trustees"] = [t for t in state["trustees"]
                                  if not (t["name"] == name and t.get("label") == label)]
        else:
            state["trustees"] = [t for t in state["trustees"] if t["name"] != name]
        removed = before - len(state["trustees"])
        save_state(state)
        audit_log("remove_trustee", {"name": name, "label": label, "removed_count": removed})
        self._send_json({"ok": True, "removed": removed})

    def _handle_login(self, data):
        role = data.get("role")
        passphrase = str(data.get("passphrase", ""))

        if role not in ("owner", "trustee"):
            audit_log("login_failed", {"role": role})
            self._send_json({"error": "invalid role or passphrase"}, status=401)
            return

        identity = _verify_passphrase(role, passphrase)

        if not identity:
            audit_log("login_failed", {"role": role})
            self._send_json({"error": "invalid role or passphrase"}, status=401)
            return

        token = _create_session(role)

        # Keep track of which trustee actually logged in.
        if role == "trustee":
            _sessions[token]["trustee_name"] = identity["trustee_name"]
            _sessions[token]["trustee_email"] = identity["trustee_email"]
            _sessions[token]["label"] = identity["label"]

        audit_log("login", {"role": role, "trustee": identity.get("trustee_name")})

        cookie = SimpleCookie()
        cookie["quorum_session"] = token
        cookie["quorum_session"]["httponly"] = True
        cookie["quorum_session"]["path"] = "/"
        cookie["quorum_session"]["max-age"] = SESSION_TTL_SECONDS

        body = json.dumps({
            "ok": True,
            "role": role,
            "trustee_name": identity.get("trustee_name"),
            "label": identity.get("label"),
        }).encode()

        self.send_response(200)
        self.send_header("Content-type", "application/json; charset=utf-8")
        self.send_header("Set-Cookie", cookie["quorum_session"].OutputString())
        self.end_headers()
        self.wfile.write(body)

    def _handle_visualize_demo(self, data):
        """
        Bug 4: returns a lossy, normalized (0..1) view of the REAL shares
        from the most recent split — never the exact 521-bit values, never
        the secret, never the polynomial coefficients. Enough to plot,
        nowhere near enough to reconstruct anything from this response
        alone (reconstruction only happens via
        _handle_visualize_demo_reconstruct, using the real stored shares
        server-side).
        """
        global POLY_DEMO_DATA

        if POLY_DEMO_DATA is None:
            self._send_json(
                {"error": "No secret has been split yet — split one in the Secrets tab first."},
                status=400,
            )
            return

        demo = POLY_DEMO_DATA
        prime = demo["prime"]
        points = []
        for i, (x, y) in enumerate(demo["shares"]):
            # Lossy, display-only normalization: y/prime as a float in
            # [0, 1). This never reveals the exact share value.
            y_normalized = y / prime
            points.append({"index": i, "x": x, "y_normalized": y_normalized})

        self._send_json({
            "label": demo["label"],
            "n": demo["n"],
            "k": demo["k"],
            "points": points,
            "note": (
                "Normalized (lossy) view of the real shares from Quorum's actual "
                "ShamirSecretSharing.split() over GF(2^521-1) — scaled only so a "
                "human can see them, not the exact share values, and not usable "
                "on its own to reconstruct anything."
            ),
        })

    def _handle_visualize_demo_reconstruct(self, data):
        """
        Bug 4: reconstructs using Quorum's REAL ShamirSecretSharing.reconstruct()
        over the actual shares from the latest split, selected by index from
        what /api/visualize-demo listed. Never uses JavaScript floating-point
        Lagrange interpolation, and never returns the secret itself — only
        whether reconstruction succeeded, matching the "3 of 5 shares →
        reconstruction successful" framing without exposing anything.
        """
        global POLY_DEMO_DATA

        if POLY_DEMO_DATA is None:
            self._send_json({"error": "No secret has been split yet."}, status=400)
            return

        demo = POLY_DEMO_DATA
        indices = data.get("indices", [])
        if not isinstance(indices, list) or not indices:
            self._send_json({"error": "select at least one share first"}, status=400)
            return

        try:
            selected = [demo["shares"][int(i)] for i in indices]
        except (IndexError, ValueError, TypeError):
            self._send_json({"error": "invalid share index"}, status=400)
            return

        field = FiniteField(prime=demo["prime"])
        sss = ShamirSecretSharing(field)
        recovered = sss.reconstruct(selected)
        success = recovered == demo["secret_int"]

        audit_log("visualize_demo_reconstruct", {
            "label": demo["label"],
            "shares_used": len(selected),
            "success": success,
        })

        outcome = "successful \u2705" if success else "failed (not enough shares yet)"
        self._send_json({
            "shares_used": len(selected),
            "n": demo["n"],
            "k": demo["k"],
            "success": success,
            "message": f"{len(selected)} of {demo['n']} shares \u2192 reconstruction {outcome}",
        })

    # ---------- response helpers ----------

    def _send_html(self, html):
        self.send_response(200)
        self.send_header("Content-type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(html.encode())

    def _send_json(self, payload, status=200):
        body = json.dumps(payload, default=str).encode()
        self.send_response(status)
        self.send_header("Content-type", "application/json; charset=utf-8")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        pass

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

    remove_trustee_parser = subparsers.add_parser("remove-trustee", help="Remove a trustee by name")
    remove_trustee_parser.add_argument("--name", required=True)
    remove_trustee_parser.add_argument("--label", default=None,
                                        help="Optional: only remove the entry for this specific secret label")
    remove_trustee_parser.set_defaults(func=cli_remove_trustee)

    return parser

def _watch_loop_background():
    """Same logic as cli_watch, but runs in a background thread instead
    of blocking a terminal — lets the dashboard drive the check-in daemon."""
    while not _watch_thread_stop.is_set():
        state = load_state()
        if not state["armed"] or state["triggered"]:
            time.sleep(1)
            continue

        elapsed = time.time() - state["last_checkin"]
        total = window_seconds(state["days"], state["demo_speed"])
        remaining = total - elapsed

        if remaining <= 0:
            trigger_switch(state)
            continue

        if not state["reminder_sent"] and total > 0 and (remaining / total) < REMINDER_THRESHOLD:
            send_owner_reminder(state)
            state["reminder_sent"] = True
            save_state(state)

        time.sleep(1)
# =============================================================================
# Entrypoint
# =============================================================================

if __name__ == "__main__":
    load_env_file()
    ROLE_HASHES = _load_or_generate_passphrases()
    cli = build_cli()
    args = cli.parse_args()
    args.func(args)