"""
Quorum — Test Suite
Track E (Zero Dependency 2026) — stdlib-only, unittest-based.

These are black-box tests: they invoke quorum.py exactly the way a user
(or a judge) would, via subprocess, and check the printed output. This
avoids assuming internal function/class names we didn't write ourselves,
and it doubles as a second layer of proof that the CLI actually works
end-to-end, not just in isolated unit calls.

Run with:
    python -m unittest tests.test_quorum -v
(from the repo root), or:
    python -m unittest test_quorum.py -v
(from inside the tests/ folder).

SAFETY: every test runs quorum.py inside a fresh, temporary, isolated
directory (a copy of quorum.py, nothing else). Nothing here ever reads,
writes, or deletes the real quorum_state.json or quorum_audit.log that
live in the repo root — those hold real project history and must never
be touched by test runs.
"""

import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


def _find_quorum_py():
    """Look for quorum.py next to this test file first (in case someone
    runs it flat, not inside tests/), then one directory up (the normal
    case: this file lives in tests/, quorum.py lives in the repo root)."""
    here = Path(__file__).parent
    candidate = here / "quorum.py"
    if candidate.exists():
        return candidate
    candidate = here.parent / "quorum.py"
    if candidate.exists():
        return candidate
    raise FileNotFoundError(
        "Could not find quorum.py next to this test file or one directory "
        "up. Run these tests from a tests/ folder inside the repo, with "
        "quorum.py in the repo root."
    )


QUORUM_SOURCE = _find_quorum_py()


def run(*args, cwd, timeout=15):
    """Run `python quorum.py <args>` inside `cwd` and return
    (returncode, stdout, stderr).

    `cwd` must be an isolated temp directory containing its own copy of
    quorum.py — never the real repo root. quorum.py writes its state
    file and audit log into the current working directory, so running
    it anywhere else risks touching real project data.

    Also forces UTF-8 for the child process's stdout: on Windows, the
    default console encoding (cp1252) can't represent characters like
    ✅ or 🚨 that quorum.py prints, and without this the child process
    crashes inside its own print() call before we can check its output.
    """
    child_env = os.environ.copy()
    child_env["PYTHONIOENCODING"] = "utf-8"
    result = subprocess.run(
        [sys.executable, "quorum.py", *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        cwd=str(cwd),
        env=child_env,
    )
    return result.returncode, result.stdout, result.stderr


def parse_shares(split_output):
    """
    Pull out the "Real shares" lines and the "Decoy (canary) shares" lines
    from `split` output. Returns (real_shares, canary_shares), each a
    list of "x:y" strings exactly as printed (ready to pass to reconstruct).
    """
    real, canary = [], []
    section = None
    for line in split_output.splitlines():
        line = line.strip()
        if line.startswith("Real shares"):
            section = "real"
            continue
        if line.startswith("Decoy"):
            section = "canary"
            continue
        m = re.match(r"^(\d+:\d+)$", line)
        if m and section == "real":
            real.append(m.group(1))
        elif m and section == "canary":
            canary.append(m.group(1))
    return real, canary


class QuorumTestCase(unittest.TestCase):
    """Base class: every test gets its own throwaway temp directory
    with a fresh copy of quorum.py, so state files / audit logs never
    collide between tests and never touch the real repo files."""

    def setUp(self):
        self.tmpdir = Path(tempfile.mkdtemp(prefix="quorum_test_"))
        shutil.copy(QUORUM_SOURCE, self.tmpdir / "quorum.py")
        self.state_file = self.tmpdir / "quorum_state.json"
        self.audit_log = self.tmpdir / "quorum_audit.log"

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def run_cmd(self, *args, timeout=15):
        return run(*args, cwd=self.tmpdir, timeout=timeout)


class TestBuildSanity(QuorumTestCase):
    """Rule/requirement-level checks, not just feature checks."""

    def test_file_compiles(self):
        result = subprocess.run(
            [sys.executable, "-m", "py_compile", str(QUORUM_SOURCE)],
            capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 0, msg=result.stderr)

    def test_help_lists_all_documented_commands(self):
        rc, out, err = self.run_cmd("--help")
        self.assertEqual(rc, 0)
        for cmd in (
            "split", "reconstruct", "visualize", "keygen",
            "encrypt-share", "decrypt-share", "arm", "checkin",
            "status", "watch", "add-trustee", "build-check",
            "list-secrets", "verify-log", "show-log",
        ):
            self.assertIn(cmd, out, msg=f"'{cmd}' missing from --help output")


class TestSplitAndReconstruct(QuorumTestCase):
    """Core SSS round-trip: this is the highest-risk part of the whole
    project per the roadmap, so it gets the most coverage."""

    def test_round_trip_recovers_exact_secret(self):
        secret = "hello world"
        rc, out, err = self.run_cmd(
            "split", secret, "--label", "Test Secret",
            "--n", "5", "--k", "3", "--canaries", "1",
        )
        self.assertEqual(rc, 0, msg=err)
        real, canary = parse_shares(out)
        self.assertEqual(len(real), 5)
        self.assertEqual(len(canary), 1)

        rc, out, err = self.run_cmd(
            "reconstruct", *real[:3], "--length", str(len(secret))
        )
        self.assertEqual(rc, 0, msg=err)
        self.assertIn(secret, out)

    def test_below_threshold_does_not_recover_secret(self):
        """K=3 means 2 shares must NOT be enough."""
        secret = "hello world"
        rc, out, err = self.run_cmd(
            "split", secret, "--label", "Below Threshold",
            "--n", "5", "--k", "3", "--canaries", "0",
        )
        real, _ = parse_shares(out)
        rc, out, err = self.run_cmd("reconstruct", *real[:2], "--length", str(len(secret)))
        self.assertNotIn(secret, out)

    def test_canary_share_trips_alert_not_silent_success(self):
        secret = "hello world"
        rc, out, err = self.run_cmd(
            "split", secret, "--label", "Canary Test",
            "--n", "5", "--k", "3", "--canaries", "1",
        )
        real, canary = parse_shares(out)
        self.assertTrue(canary, "split did not produce a canary share")

        rc, out, err = self.run_cmd(
            "reconstruct", real[0], real[1], canary[0],
            "--length", str(len(secret)),
        )
        combined = out + err
        self.assertTrue(
            "ALERT" in combined or "canary" in combined.lower(),
            msg=f"canary share was used but no alert was raised. Output:\n{combined}",
        )
        self.assertNotIn(secret, out)

    def test_k_equals_n_requires_all_shares(self):
        """Edge case: K == N — every single share is required."""
        secret = "abc"
        rc, out, err = self.run_cmd(
            "split", secret, "--label", "K equals N",
            "--n", "3", "--k", "3", "--canaries", "0",
        )
        real, _ = parse_shares(out)
        self.assertEqual(len(real), 3)

        rc, out, err = self.run_cmd("reconstruct", *real[:2], "--length", str(len(secret)))
        self.assertNotIn(secret, out)

        rc, out, err = self.run_cmd("reconstruct", *real, "--length", str(len(secret)))
        self.assertIn(secret, out)

    def test_k_equals_1_any_single_share_suffices(self):
        """Edge case: K == 1 — degenerate but must still work."""
        secret = "x"
        rc, out, err = self.run_cmd(
            "split", secret, "--label", "K equals 1",
            "--n", "3", "--k", "1", "--canaries", "0",
        )
        real, _ = parse_shares(out)
        rc, out, err = self.run_cmd("reconstruct", real[0], "--length", str(len(secret)))
        self.assertIn(secret, out)

    def test_duplicate_shares_do_not_falsely_satisfy_threshold(self):
        """Using the same share twice must not count as 2 distinct shares."""
        secret = "hello world"
        rc, out, err = self.run_cmd(
            "split", secret, "--label", "Duplicate Shares",
            "--n", "5", "--k", "3", "--canaries", "0",
        )
        real, _ = parse_shares(out)
        rc, out, err = self.run_cmd(
            "reconstruct", real[0], real[0], real[0],
            "--length", str(len(secret)),
        )
        self.assertNotIn(secret, out)

    def test_tampered_share_does_not_silently_recover_wrong_secret_as_correct(self):
        """Corrupt one digit of a share's y-value; reconstruction should
        either fail loudly or simply not produce the original secret."""
        secret = "hello world"
        rc, out, err = self.run_cmd(
            "split", secret, "--label", "Tampered Share",
            "--n", "5", "--k", "3", "--canaries", "0",
        )
        real, _ = parse_shares(out)
        x, y = real[0].split(":")
        tampered = f"{x}:{y[:-1]}{'0' if y[-1] != '0' else '1'}"
        rc, out, err = self.run_cmd(
            "reconstruct", tampered, real[1], real[2],
            "--length", str(len(secret)),
        )
        self.assertNotIn(secret, out)


class TestDeadMansSwitch(QuorumTestCase):
    """Timer / check-in orchestration, using --demo-speed so tests stay fast."""

    def test_arm_then_immediate_status_shows_time_remaining(self):
        rc, out, err = self.run_cmd("arm", "--days", "5", "--demo-speed")
        self.assertEqual(rc, 0, msg=err)
        rc, out, err = self.run_cmd("status")
        self.assertIn("remaining", out.lower())

    def test_checkin_resets_timer(self):
        self.run_cmd("arm", "--days", "5", "--demo-speed")
        rc, out, err = self.run_cmd("checkin")
        self.assertEqual(rc, 0, msg=err)
        rc, out, err = self.run_cmd("status")
        self.assertIn("remaining", out.lower())


class TestAuditLog(QuorumTestCase):
    """Chain of Custody — tamper-evidence is a core claimed feature,
    so we test both the happy path and the actual tamper-detection path."""

    def test_verify_log_passes_on_untouched_log(self):
        self.run_cmd("split", "abc", "--label", "Audit Sanity", "--n", "3", "--k", "2")
        rc, out, err = self.run_cmd("verify-log")
        self.assertEqual(rc, 0, msg=err)
        self.assertIn("verified", out.lower())

    def test_verify_log_detects_manual_corruption(self):
        self.run_cmd("split", "abc", "--label", "Audit Tamper", "--n", "3", "--k", "2")
        self.run_cmd("checkin")  # add a second entry so there's a chain to break

        self.assertTrue(self.audit_log.exists(), "audit log file was not created")
        lines = self.audit_log.read_text().splitlines()
        self.assertTrue(lines, "audit log is empty, nothing to tamper with")

        corrupted = lines[0].replace("0", "9", 1) if "0" in lines[0] else lines[0] + "x"
        lines[0] = corrupted
        self.audit_log.write_text("\n".join(lines) + "\n")

        rc, out, err = self.run_cmd("verify-log")
        combined = (out + err).lower()
        self.assertTrue(
            "tamper" in combined or "broken" in combined or "invalid" in combined
            or rc != 0,
            msg=f"verify-log did not flag a corrupted log entry. Output:\n{out}\n{err}",
        )


class TestBuildCheck(QuorumTestCase):
    """Reproducible-build bonus proof: hashing the same file twice must
    produce identical output."""

    def test_build_check_is_deterministic(self):
        rc1, out1, err1 = self.run_cmd("build-check", "--file", "quorum.py")
        rc2, out2, err2 = self.run_cmd("build-check", "--file", "quorum.py")
        self.assertEqual(rc1, 0, msg=err1)
        self.assertEqual(rc2, 0, msg=err2)
        hash1 = re.search(r"[0-9a-fA-F]{16,}", out1)
        hash2 = re.search(r"[0-9a-fA-F]{16,}", out2)
        self.assertIsNotNone(hash1, "no hash found in build-check output")
        self.assertEqual(hash1.group(), hash2.group())


if __name__ == "__main__":
    unittest.main(verbosity=2)