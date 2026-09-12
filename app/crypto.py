"""
Signing and hashing primitives.

Two different mechanisms, used for two different guarantees:

1. Policy signatures (HMAC-SHA256, server secret).
   Every policy row carries a signature over its enforceable fields.
   The signature can only be produced by something holding
   SIGNING_SECRET (the service itself, via the signed write path). A
   direct database write that changes `action` without going through
   that path leaves a stale signature behind — the engine catches this
   at evaluation time and treats the policy as untrusted rather than
   silently enforcing a mutated rule.

2. Audit chain hashes (plain SHA-256, no secret).
   Each audit block hashes its own content plus the previous block's
   hash, exactly like a blockchain. This doesn't need a secret — the
   point isn't to keep the hash secret, it's to make any retroactive
   edit to block N detectable by recomputing the chain from block 0
   and seeing where it diverges.
"""
import hashlib
import hmac
import json


def canonical(obj):
    """Deterministic JSON: recursively sort dict keys so the same
    logical content always serializes to the same bytes, regardless of
    field insertion order."""

    def sort(value):
        if isinstance(value, list):
            return [sort(v) for v in value]
        if isinstance(value, dict):
            return {k: sort(value[k]) for k in sorted(value.keys())}
        return value

    return json.dumps(sort(obj), separators=(",", ":"), ensure_ascii=False)


def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


POLICY_SIGNED_FIELDS = ["name", "domain", "priority", "enabled", "conditions", "action"]


def sign_policy(policy: dict, secret: str) -> str:
    """HMAC-SHA256 over the policy's enforceable fields. Anything not
    in POLICY_SIGNED_FIELDS (e.g. internal bookkeeping) is intentionally
    excluded so unrelated metadata can't cause spurious signature drift."""
    content = {field: policy.get(field) for field in POLICY_SIGNED_FIELDS}
    payload = "POLICY|" + canonical(content)
    return hmac.new(secret.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).hexdigest()


def verify_policy_signature(policy: dict, secret: str) -> bool:
    expected = sign_policy(policy, secret)
    actual = policy.get("signature", "")
    # Constant-time comparison: signature checks should never leak
    # timing information about how much of the signature matched.
    return hmac.compare_digest(expected, actual)


def chain_block_hash(prev_hash: str, content: dict) -> str:
    return sha256_hex(prev_hash + "|" + canonical(content))
