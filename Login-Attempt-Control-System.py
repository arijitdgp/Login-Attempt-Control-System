"""
Login Attempt Control System
------------------------------------
Limits repeated incorrect password attempts. After MAX_ATTEMPTS consecutive
failures, the account is temporarily locked for LOCKOUT_SECONDS.

Features
  * Passwords stored as salted PBKDF2 hashes (never plain text)
  * Constant-time hash comparison (hmac.compare_digest)
  * Per-user failure counter and lockout timer
  * Counter resets after a successful login
  * Lockout expires automatically
  * Locked accounts reject even the correct password (this is what stops
    brute-force guessing)

Run:
    python Login-Attempt-Control-System.py          -> interactive login
    python Login-Attempt-Control-System.py --demo   -> automatic demonstration (no typing needed)
"""

import hashlib
import hmac
import os
import sys
import time
from getpass import getpass

MAX_ATTEMPTS = 3        # failures allowed before lockout
LOCKOUT_SECONDS = 30    # how long the account stays locked


def hash_password(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100_000)


class LoginSystem:
    def __init__(self, max_attempts=MAX_ATTEMPTS, lockout_seconds=LOCKOUT_SECONDS,
                 clock=time.monotonic):
        self.max_attempts = max_attempts
        self.lockout_seconds = lockout_seconds
        self.clock = clock                # injectable so the demo can fast-forward
        self.users = {}                   # username -> (salt, hash)
        self.failures = {}                # username -> consecutive failed attempts
        self.locked_until = {}            # username -> clock time when lock ends

    # ---- user management -------------------------------------------------
    def register(self, username: str, password: str) -> None:
        salt = os.urandom(16)
        self.users[username] = (salt, hash_password(password, salt))
        self.failures[username] = 0

    # ---- lockout helpers -------------------------------------------------
    def remaining_lock(self, username: str) -> int:
        """Seconds of lockout left (0 if not locked)."""
        until = self.locked_until.get(username)
        if until is None:
            return 0
        left = until - self.clock()
        if left <= 0:                     # lock expired -> clean slate
            del self.locked_until[username]
            self.failures[username] = 0
            return 0
        return int(left) + 1

    # ---- main entry point ------------------------------------------------
    def login(self, username: str, password: str) -> tuple[bool, str]:
        # Unknown user: do the same work and give the same message as a wrong
        # password so attackers can't discover which usernames exist.
        if username not in self.users:
            hash_password(password, b"\x00" * 16)
            return False, "Invalid username or password."

        left = self.remaining_lock(username)
        if left:
            return False, f"Account locked. Try again in {left} second(s)."

        salt, stored = self.users[username]
        if hmac.compare_digest(stored, hash_password(password, salt)):
            self.failures[username] = 0
            return True, "Login successful. Welcome!"

        self.failures[username] += 1
        remaining = self.max_attempts - self.failures[username]
        if remaining <= 0:
            self.locked_until[username] = self.clock() + self.lockout_seconds
            return False, (f"Too many failed attempts. Account locked for "
                           f"{self.lockout_seconds} seconds.")
        return False, f"Invalid username or password. {remaining} attempt(s) left."


# ---------------------------------------------------------------------------
# Demo (simulated clock, so it runs instantly)
# ---------------------------------------------------------------------------
def run_demo() -> None:
    fake_time = [0.0]
    system = LoginSystem(clock=lambda: fake_time[0])
    system.register("alice", "Secret#123")

    def attempt(pw):
        ok, msg = system.login("alice", pw)
        print(f"  [t={fake_time[0]:>4.0f}s] password={pw!r:<14} -> {msg}")

    print(f"Policy: {MAX_ATTEMPTS} failures -> {LOCKOUT_SECONDS}s lockout\n")
    print("1) Three wrong passwords:")
    for pw in ("wrong1", "wrong2", "wrong3"):
        attempt(pw)

    print("\n2) Correct password while locked (still rejected):")
    fake_time[0] += 5
    attempt("Secret#123")

    print("\n3) After the lockout expires:")
    fake_time[0] += LOCKOUT_SECONDS
    attempt("Secret#123")


# ---------------------------------------------------------------------------
# Interactive mode
# ---------------------------------------------------------------------------
def run_interactive() -> None:
    system = LoginSystem()
    system.register("admin", "Pass@123")
    print("=== Login System ===")
    print("Demo account -> username: admin | password: Pass@123")
    print(f"{MAX_ATTEMPTS} wrong attempts lock the account for {LOCKOUT_SECONDS}s. Ctrl+C to quit.\n")
    try:
        while True:
            user = input("Username: ").strip()
            pw = getpass("Password: ")
            ok, msg = system.login(user, pw)
            print(msg, "\n")
            if ok:
                break
    except (KeyboardInterrupt, EOFError):
        print("\nExiting.")


if __name__ == "__main__":
    run_demo() if "--demo" in sys.argv else run_interactive()
