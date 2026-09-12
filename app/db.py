"""
Thin data-access layer over sqlite3 (standard library only — no ORM
dependency). One connection per request, opened lazily and cached on
Flask's `g`, closed automatically when the request ends.
"""
import datetime
import json
import sqlite3

from flask import current_app, g

SCHEMA = """
CREATE TABLE IF NOT EXISTS policies (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    domain      TEXT NOT NULL,
    priority    INTEGER NOT NULL,
    enabled     INTEGER NOT NULL,
    action      TEXT NOT NULL,
    conditions  TEXT NOT NULL,   -- JSON
    signature   TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_blocks (
    idx         INTEGER PRIMARY KEY AUTOINCREMENT,
    kind        TEXT NOT NULL,
    domain      TEXT NOT NULL,
    action      TEXT NOT NULL,
    explanation TEXT NOT NULL,
    policy_id   TEXT,
    policy_name TEXT,
    prev_hash   TEXT NOT NULL,
    hash        TEXT NOT NULL,
    created_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS quarantine_items (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ref         TEXT NOT NULL,
    domain      TEXT NOT NULL,
    status      TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    released_at TEXT
);
"""


def _now() -> str:
    return datetime.datetime.utcnow().isoformat() + "Z"


def get_db() -> sqlite3.Connection:
    if "db" not in g:
        g.db = sqlite3.connect(current_app.config["DATABASE_PATH"])
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


def close_db(exception=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db(app):
    with app.app_context():
        db = get_db()
        db.executescript(SCHEMA)
        db.commit()
    app.teardown_appcontext(close_db)


# ---------------------------------------------------------------- policies

def policy_row_to_dict(row: sqlite3.Row, include_signature=False) -> dict:
    d = {
        "id": row["id"], "name": row["name"], "domain": row["domain"],
        "priority": row["priority"], "enabled": bool(row["enabled"]),
        "action": row["action"], "conditions": json.loads(row["conditions"]),
    }
    if include_signature:
        d["signature"] = row["signature"]
    return d


def list_policies(domain: str = None) -> list:
    db = get_db()
    if domain:
        rows = db.execute(
            "SELECT * FROM policies WHERE domain = ? ORDER BY priority", (domain,)
        ).fetchall()
    else:
        rows = db.execute("SELECT * FROM policies ORDER BY domain, priority").fetchall()
    return rows


def get_policy(policy_id: str):
    db = get_db()
    return db.execute("SELECT * FROM policies WHERE id = ?", (policy_id,)).fetchone()


def upsert_policy(policy: dict):
    db = get_db()
    db.execute(
        """INSERT INTO policies (id, name, domain, priority, enabled, action, conditions, signature, updated_at)
           VALUES (:id, :name, :domain, :priority, :enabled, :action, :conditions, :signature, :updated_at)
           ON CONFLICT(id) DO UPDATE SET
             name=excluded.name, domain=excluded.domain, priority=excluded.priority,
             enabled=excluded.enabled, action=excluded.action, conditions=excluded.conditions,
             signature=excluded.signature, updated_at=excluded.updated_at""",
        {
            "id": policy["id"], "name": policy["name"], "domain": policy["domain"],
            "priority": policy["priority"], "enabled": int(policy["enabled"]),
            "action": policy["action"], "conditions": json.dumps(policy["conditions"]),
            "signature": policy["signature"], "updated_at": _now(),
        },
    )
    db.commit()


def update_policy_fields(policy_id: str, fields: dict, new_signature: str):
    db = get_db()
    row = get_policy(policy_id)
    merged = policy_row_to_dict(row)
    merged.update({k: v for k, v in fields.items() if k in
                   ("name", "priority", "enabled", "action", "conditions")})
    merged["id"] = policy_id
    merged["signature"] = new_signature
    upsert_policy(merged)
    return get_policy(policy_id)


def delete_policy(policy_id: str):
    db = get_db()
    db.execute("DELETE FROM policies WHERE id = ?", (policy_id,))
    db.commit()


def force_set_action(policy_id: str, action: str):
    """Rogue path: changes `action` only, leaves `signature` untouched
    and stale on purpose — this is what makes tamper detection catchable."""
    db = get_db()
    db.execute("UPDATE policies SET action = ? WHERE id = ?", (action, policy_id))
    db.commit()


# ---------------------------------------------------------------- audit chain

def audit_block_to_dict(row: sqlite3.Row) -> dict:
    return {
        "idx": row["idx"], "kind": row["kind"], "domain": row["domain"],
        "action": row["action"], "explanation": row["explanation"],
        "policy_id": row["policy_id"], "policy_name": row["policy_name"],
        "prev_hash": row["prev_hash"], "hash": row["hash"], "created_at": row["created_at"],
    }


def audit_block_content(row: sqlite3.Row) -> dict:
    return {
        "domain": row["domain"], "action": row["action"], "explanation": row["explanation"],
        "policy_id": row["policy_id"], "policy_name": row["policy_name"],
    }


def list_audit_blocks() -> list:
    db = get_db()
    return db.execute("SELECT * FROM audit_blocks ORDER BY idx").fetchall()


def last_audit_hash() -> str:
    db = get_db()
    row = db.execute("SELECT hash FROM audit_blocks ORDER BY idx DESC LIMIT 1").fetchone()
    return row["hash"] if row else "0" * 64


def append_audit_block(kind, domain, action, explanation, prev_hash, block_hash,
                        policy_id=None, policy_name=None):
    db = get_db()
    db.execute(
        """INSERT INTO audit_blocks (kind, domain, action, explanation, policy_id, policy_name,
                                      prev_hash, hash, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (kind, domain, action, explanation, policy_id, policy_name, prev_hash, block_hash, _now()),
    )
    db.commit()


# ---------------------------------------------------------------- quarantine

def quarantine_row_to_dict(row: sqlite3.Row) -> dict:
    return {
        "id": row["id"], "ref": row["ref"], "domain": row["domain"], "status": row["status"],
        "created_at": row["created_at"], "released_at": row["released_at"],
    }


def list_quarantine() -> list:
    db = get_db()
    return db.execute("SELECT * FROM quarantine_items ORDER BY created_at DESC").fetchall()


def get_quarantine_item(item_id: int):
    db = get_db()
    return db.execute("SELECT * FROM quarantine_items WHERE id = ?", (item_id,)).fetchone()


def add_quarantine_item(ref: str, domain: str, status: str):
    db = get_db()
    db.execute(
        "INSERT INTO quarantine_items (ref, domain, status, created_at) VALUES (?, ?, ?, ?)",
        (ref, domain, status, _now()),
    )
    db.commit()


def release_quarantine_item(item_id: int):
    db = get_db()
    db.execute(
        "UPDATE quarantine_items SET status = 'released', released_at = ? WHERE id = ?",
        (_now(), item_id),
    )
    db.commit()
