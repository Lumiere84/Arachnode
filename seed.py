"""
Seeds the policy library — the same seven policies shown in the
Arachnode AI Policy Console demo, so the console and the real backend
tell the same story. Run once against a fresh database:

    python seed.py
"""
from app import create_app
from app.crypto import sign_policy
from app import db as arachnode_db

POLICIES = [
    dict(
        id="p-priv-esc", name="Capture agent attempting privilege escalation",
        domain="threat", priority=5, enabled=True, action="capture",
        conditions=[
            {"field": "agent.requested_scope", "operator": "eq", "value": "admin"},
            {"field": "agent.granted_scope", "operator": "ne", "value": "admin"},
        ],
    ),
    dict(
        id="p-access-deny", name="Deny contractors on restricted resources",
        domain="access", priority=10, enabled=True, action="deny",
        conditions=[
            {"field": "actor.role", "operator": "eq", "value": "contractor"},
            {"field": "resource.classification", "operator": "eq", "value": "restricted"},
        ],
    ),
    dict(
        id="p-beacon", name="Capture on high-confidence beaconing",
        domain="threat", priority=10, enabled=True, action="capture",
        conditions=[
            {"field": "signal", "operator": "eq", "value": "beaconing_pattern"},
            {"field": "anomaly_score", "operator": "gt", "value": 0.85},
        ],
    ),
    dict(
        id="p-hf-incident", name="Quarantine unscanned public-hub models with malicious layers",
        domain="data_governance", priority=10, enabled=True, action="quarantine",
        conditions=[
            {"field": "artifact.origin", "operator": "eq", "value": "public_hub"},
            {"field": "artifact.scan_result.malicious_layer_detected", "operator": "eq", "value": True},
        ],
    ),
    dict(
        id="p-rate", name="Quarantine agent exceeding tool-call rate",
        domain="threat", priority=15, enabled=True, action="quarantine",
        conditions=[{"field": "agent.tool_calls_per_min", "operator": "gt", "value": 50}],
    ),
    dict(
        id="p-exfil", name="Quarantine agent-initiated weight exfiltration",
        domain="data_governance", priority=15, enabled=True, action="quarantine",
        conditions=[
            {"field": "agent.action", "operator": "eq", "value": "export_weights"},
            {"field": "artifact.classification", "operator": "eq", "value": "restricted"},
        ],
    ),
    dict(
        id="p-access-allow", name="Allow employees on internal resources",
        domain="access", priority=20, enabled=True, action="allow",
        conditions=[
            {"field": "actor.role", "operator": "eq", "value": "employee"},
            {"field": "resource.classification", "operator": "in", "value": ["internal", "public"]},
        ],
    ),
]


def seed(app=None):
    app = app or create_app()
    with app.app_context():
        secret = app.config["SIGNING_SECRET"]
        for spec in POLICIES:
            arachnode_db.upsert_policy({**spec, "signature": sign_policy(spec, secret)})
        print(f"Seeded {len(POLICIES)} policies across "
              f"{len({p['domain'] for p in POLICIES})} domains.")


if __name__ == "__main__":
    seed()
