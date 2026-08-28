"""
Quorum — a stdlib-only dead-man's-switch secret sharing tool.

If the owner doesn't check in within a configured window, trustees can
combine their shares (via Shamir's Secret Sharing) to reconstruct a
protected secret. Shares are distributed to trustees using Diffie-Hellman
key exchange, so the secret itself never crosses an insecure channel.
Decoy "canary" shares detect coerced or leaked reconstruction attempts.

Zero third-party runtime dependencies — Python standard library only.
"""

# =============================================================================
# Imports
# =============================================================================

import argparse
import hashlib
import http.server
import secrets
import socketserver
import threading
import webbrowser


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


def derive_key(shared_secret_int, length=32):
    """Hash the raw DH shared secret into a fixed-length symmetric key."""
    secret_bytes = shared_secret_int.to_bytes(
        (shared_secret_int.bit_length() + 7) // 8, "big"
    )
    return hashlib.sha256(secret_bytes).digest()  # 32 bytes


def xor_encrypt(data: bytes, key: bytes) -> bytes:
    """
    XOR stream cipher keyed by a SHA-256-derived key (repeated to match length).

    Note: provides confidentiality only, not tamper-detection/integrity —
    see the threat model doc for this documented scope boundary.
    """
    full_key = (key * (len(data) // len(key) + 1))[:len(data)]
    return bytes(d ^ k for d, k in zip(data, full_key))


def xor_decrypt(data: bytes, key: bytes) -> bytes:
    """XOR is symmetric — decryption is identical to encryption."""
    return xor_encrypt(data, key)


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
# CLI command handlers
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

    print(f"Secret split into {args.n} shares, threshold {args.k}.")
    print(f"(length={len(secret_bytes)} bytes — you'll need this to reconstruct)\n")

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
        print("🚨 ALERT: canary share detected in reconstruction attempt!")
        print(f"   {len(tripped)} decoy share(s) used — this looks like a leaked or coerced share.")
        for x, y in tripped:
            print(f"   Tripped canary at x={x}")
        return

    recovered_int = sss.reconstruct(shares)
    recovered_bytes = int_to_secret(recovered_int, args.length)

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
    """Encrypt a share for a trustee using a DH-derived shared key."""
    dh = DiffieHellman()
    dh.private_key = args.my_private
    shared = dh.shared_secret(args.their_public)
    key = derive_key(shared)

    encrypted = xor_encrypt(args.share.encode(), key)
    print("Encrypted share (hex, safe to send over an insecure channel):")
    print(encrypted.hex())


def cli_decrypt_share(args):
    """Decrypt a share received from the owner using a DH-derived shared key."""
    dh = DiffieHellman()
    dh.private_key = args.my_private
    shared = dh.shared_secret(args.their_public)
    key = derive_key(shared)

    encrypted = bytes.fromhex(args.encrypted_hex)
    decrypted = xor_decrypt(encrypted, key)
    print("Decrypted share:")
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
# CLI argument parser
# =============================================================================

def build_cli():
    """Build the top-level argparse CLI with all subcommands registered."""
    parser = argparse.ArgumentParser(
        prog="quorum",
        description="Quorum — dead-man's-switch secret sharing, built from stdlib only."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    split_parser = subparsers.add_parser("split", help="Split a secret into shares")
    split_parser.add_argument("secret", help="The secret to split (as plain text)")
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

    return parser


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
  // Small human-scale demo values, purely for visualization clarity.
  // Real secret/shares in the CLI use a full 521-bit prime — this is illustrative only.
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
    if (revealed.length < 3) return; // need k=3 points to determine the curve
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
# Entrypoint
# =============================================================================

if __name__ == "__main__":
    cli = build_cli()
    args = cli.parse_args()
    args.func(args)