"""Pure unit tests for app.engine.evaluate — no Flask, no database.
Mirrors the eight demo scenarios from the Arachnode AI Policy Console,
so the real backend is checked against the same expectations the
console's own scenario buttons advertise.

Run with:  python -m unittest discover -s tests
"""
import unittest

from app.crypto import sign_policy
from app.engine import evaluate
from seed import POLICIES

SECRET = "unit-test-secret"
SIGNED_POLICIES = [{**p, "signature": sign_policy(p, SECRET)} for p in POLICIES]

SCENARIOS = [
    ("malicious_model_upload", "data_governance",
     {"artifact": {"origin": "public_hub", "scan_result": {"malicious_layer_detected": True}}},
     "quarantine"),
    ("clean_model_upload", "data_governance",
     {"artifact": {"origin": "public_hub", "scan_result": {"malicious_layer_detected": False}}},
     "allow"),
    ("agent_requests_admin_scope", "threat",
     {"agent": {"requested_scope": "admin", "granted_scope": "read_only"}},
     "capture"),
    ("agent_tool_call_rate_spike", "threat",
     {"agent": {"tool_calls_per_min": 340}},
     "quarantine"),
    ("agent_exfiltrates_weights", "data_governance",
     {"agent": {"action": "export_weights"}, "artifact": {"classification": "restricted"}},
     "quarantine"),
    ("contractor_to_restricted_resource", "access",
     {"actor": {"role": "contractor"}, "resource": {"classification": "restricted"}},
     "deny"),
    ("employee_to_internal_resource", "access",
     {"actor": {"role": "employee"}, "resource": {"classification": "internal"}},
     "allow"),
    ("beaconing_c2_signal", "threat",
     {"source_ip": "203.0.113.7", "signal": "beaconing_pattern", "anomaly_score": 0.93},
     "capture"),
]


class TestScenarios(unittest.TestCase):
    def test_all_demo_scenarios(self):
        for label, domain, payload, expected in SCENARIOS:
            with self.subTest(label):
                decision = evaluate(domain, payload, SIGNED_POLICIES, SECRET)
                self.assertEqual(decision.action, expected, decision.explanation)

    def test_unmatched_field_fails_closed(self):
        """A condition referencing a field the payload doesn't have
        should fail to match, not raise."""
        decision = evaluate("access", {"actor": {"role": "employee"}}, SIGNED_POLICIES, SECRET)
        self.assertEqual(decision.action, "deny")  # resource.classification missing -> default

    def test_rogue_edit_is_detected_and_skipped(self):
        tampered = [dict(p) for p in SIGNED_POLICIES]
        target = next(p for p in tampered if p["id"] == "p-access-allow")
        target["action"] = "deny"  # mutated in place; signature now stale

        decision = evaluate(
            "access",
            {"actor": {"role": "employee"}, "resource": {"classification": "internal"}},
            tampered, SECRET,
        )
        self.assertIn("p-access-allow", decision.tampered)
        self.assertEqual(decision.action, "deny")  # falls through to domain default
        self.assertIsNone(decision.policy_id)  # no *trusted* policy matched

    def test_signed_edit_is_trusted(self):
        edited = [dict(p) for p in SIGNED_POLICIES]
        target = next(p for p in edited if p["id"] == "p-access-allow")
        target["action"] = "deny"
        target["signature"] = sign_policy(target, SECRET)  # properly re-signed

        decision = evaluate(
            "access",
            {"actor": {"role": "employee"}, "resource": {"classification": "internal"}},
            edited, SECRET,
        )
        self.assertEqual(decision.tampered, [])
        self.assertEqual(decision.policy_id, "p-access-allow")
        self.assertEqual(decision.action, "deny")

    def test_signature_is_secret_dependent(self):
        """A signature produced with the wrong secret must not verify —
        otherwise the tamper-detection story is theater."""
        wrong = [{**p, "signature": sign_policy(p, "a-different-secret")} for p in POLICIES]
        decision = evaluate("threat", {"agent": {"tool_calls_per_min": 340}}, wrong, SECRET)
        self.assertTrue(decision.tampered)
        self.assertEqual(decision.action, "allow")  # threat domain default


if __name__ == "__main__":
    unittest.main()
