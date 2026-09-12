"""
The evaluation engine.

This is the decision core: given a domain and an event payload, walk
the enabled policies for that domain in priority order, skip any whose
signature doesn't match its content (tampered), and return the first
one whose conditions all match. If nothing matches — or every
candidate was tampered — fall back to the domain's default action.

This is a pure function of (policies, domain, payload): no I/O, no
database, so it's trivially unit-testable and the same logic that runs
in the Flask route also runs standalone in tests/test_engine.py.
"""
import re
from dataclasses import dataclass, field
from typing import Any

from app.crypto import verify_policy_signature

DEFAULT_ACTION = {
    "access": "deny",
    "threat": "allow",
    "data_governance": "allow",
}

VALID_DOMAINS = frozenset(DEFAULT_ACTION.keys())
VALID_ACTIONS = frozenset({"allow", "deny", "quarantine", "capture"})


def _lookup(payload: dict, path: str):
    """Resolve a dotted field path (e.g. 'agent.requested_scope')
    against the payload. Returns (value, found) rather than raising, so
    a missing field is a normal non-match instead of an error."""
    cur = payload
    for part in path.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None, False
    return cur, True


def _op_in(a, b):
    return isinstance(b, (list, tuple)) and a in b


def _op_not_in(a, b):
    return isinstance(b, (list, tuple)) and a not in b


def _op_gt(a, b):
    return a is not None and a > b


def _op_lt(a, b):
    return a is not None and a < b


def _op_contains(a, b):
    return a is not None and str(b) in str(a)


def _op_matches(a, b):
    return a is not None and re.search(b, str(a)) is not None


OPS = {
    "eq": lambda a, b: a == b,
    "ne": lambda a, b: a != b,
    "in": _op_in,
    "not_in": _op_not_in,
    "gt": _op_gt,
    "lt": _op_lt,
    "contains": _op_contains,
    "matches": _op_matches,
}


def condition_matches(condition: dict, payload: dict) -> bool:
    value, found = _lookup(payload, condition["field"])
    if not found:
        return False
    op = OPS.get(condition["operator"])
    if op is None:
        return False
    return bool(op(value, condition["value"]))


def explain(policy: dict) -> str:
    clause = " AND ".join(
        f"{c['field']} {c['operator']} {c['value']!r}" for c in policy["conditions"]
    )
    return f"{clause} -> {policy['action']} (policy: {policy['name']})"


@dataclass
class Decision:
    action: str
    explanation: str
    policy_id: "str | None" = None
    policy_name: "str | None" = None
    tampered: list = field(default_factory=list)

    def as_dict(self):
        return {
            "action": self.action,
            "explanation": self.explanation,
            "policy_id": self.policy_id,
            "policy_name": self.policy_name,
            "tampered": self.tampered,
        }


def evaluate(domain: str, payload: dict, policies: list, signing_secret: str) -> Decision:
    """policies: list of dicts with at least
    id, name, domain, priority, enabled, action, conditions, signature."""
    pool = sorted(
        (p for p in policies if p["domain"] == domain and p["enabled"]),
        key=lambda p: p["priority"],
    )

    tampered = []
    for policy in pool:
        if not verify_policy_signature(policy, signing_secret):
            tampered.append(policy["id"])
            continue
        if all(condition_matches(c, payload) for c in policy["conditions"]):
            return Decision(
                action=policy["action"],
                explanation=explain(policy),
                policy_id=policy["id"],
                policy_name=policy["name"],
                tampered=tampered,
            )

    default = DEFAULT_ACTION.get(domain, "deny")
    return Decision(
        action=default,
        explanation=f"No enabled policy matched domain '{domain}' -> default '{default}'",
        tampered=tampered,
    )
