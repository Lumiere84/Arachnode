"""
Configuration for the Arachnode AI policy engine.

Two secrets matter here, and they are deliberately different:

- SIGNING_SECRET   held by the service itself. Used to HMAC-sign every
                    policy record on write, so the engine can tell a
                    write that went through its own API (signed) from a
                    row mutated directly in the database (unsigned/rogue).
- DISCERNMENT_KEY   held out-of-band by a human approver, never stored
                    next to the data it protects. Required for any
                    action that *loosens* enforcement: setting a policy
                    to ALLOW, or releasing something from quarantine.
                    A compromised process holding SIGNING_SECRET can
                    still forge a signature; it cannot loosen anything
                    without this key.

Both default to dev-only values so the app runs out of the box; set
real values via environment variables before deploying anywhere real.

Storage is plain sqlite3 (standard library) — no ORM dependency to
install, which also means no network access is required to stand this
service up.
"""
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


class Config:
    DATABASE_PATH = os.environ.get(
        "ARACHNODE_DATABASE_PATH", os.path.join(BASE_DIR, "arachnode.db")
    )

    SIGNING_SECRET = os.environ.get("ARACHNODE_SIGNING_SECRET", "dev-signing-secret-change-me")
    DISCERNMENT_KEY = os.environ.get("ARACHNODE_DISCERNMENT_KEY", "dev-discernment-key-change-me")

    # HTTP Basic Auth in front of the whole app (console included) — see
    # app/auth.py. This is the "front door"; the Discernment Key is a
    # second lock on two specific actions *inside* that door, not a
    # substitute for having one.
    ADMIN_USER = os.environ.get("ARACHNODE_ADMIN_USER", "admin")
    ADMIN_PASSWORD = os.environ.get("ARACHNODE_ADMIN_PASSWORD", "dev-admin-password-change-me")

    JSON_SORT_KEYS = False

    DEV_DEFAULTS = {
        "ARACHNODE_SIGNING_SECRET": "dev-signing-secret-change-me",
        "ARACHNODE_DISCERNMENT_KEY": "dev-discernment-key-change-me",
        "ARACHNODE_ADMIN_PASSWORD": "dev-admin-password-change-me",
    }
