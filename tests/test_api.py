"""End-to-end tests through the Flask API: fire events, walk the audit
chain, exercise the Discernment Key gate on both places it applies, and
the Basic Auth front door in front of all of it.

Run with:  python -m unittest discover -s tests
"""
import os
import tempfile
import unittest

from flask.testing import FlaskClient

from app import create_app, db as arachnode_db
from seed import seed as seed_db


class TestConfig:
    SIGNING_SECRET = "test-signing-secret"
    DISCERNMENT_KEY = "test-discernment-key"
    ADMIN_USER = "test-admin"
    ADMIN_PASSWORD = "test-admin-password"
    TESTING = True
    DEBUG = True
    DATABASE_PATH = None  # set per-test in setUp


class _AuthenticatedClient(FlaskClient):
    """Every other test in this module is about the API's own logic,
    not the front door — so this client logs in automatically, the way
    a browser would after its one Basic Auth prompt. TestLoginRequired
    below uses the plain client instead, precisely to test that door."""

    def open(self, *args, **kwargs):
        kwargs.setdefault("auth", (TestConfig.ADMIN_USER, TestConfig.ADMIN_PASSWORD))
        return super().open(*args, **kwargs)


class ApiTestCase(unittest.TestCase):
    def setUp(self):
        fd, path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        self.db_path = path
        TestConfig.DATABASE_PATH = path

        self.app = create_app(config_object=TestConfig)
        seed_db(self.app)
        self.app.test_client_class = _AuthenticatedClient
        self.client = self.app.test_client()

    def tearDown(self):
        os.remove(self.db_path)


class TestLoginRequired(ApiTestCase):
    """Uses the plain (unauthenticated) test client on purpose."""

    def setUp(self):
        super().setUp()
        self.app.test_client_class = FlaskClient  # undo the auto-auth override for this class
        self.anon = self.app.test_client()

    def test_health_needs_no_login(self):
        resp = self.anon.get("/health")
        self.assertEqual(resp.status_code, 200)

    def test_console_requires_login(self):
        resp = self.anon.get("/")
        self.assertEqual(resp.status_code, 401)
        self.assertIn("Basic", resp.headers.get("WWW-Authenticate", ""))

    def test_api_requires_login(self):
        self.assertEqual(self.anon.get("/policies").status_code, 401)
        self.assertEqual(self.anon.post("/events", json={}).status_code, 401)

    def test_wrong_password_is_rejected(self):
        resp = self.anon.get("/policies", auth=(TestConfig.ADMIN_USER, "not-the-password"))
        self.assertEqual(resp.status_code, 401)

    def test_correct_credentials_pass(self):
        resp = self.anon.get("/policies", auth=(TestConfig.ADMIN_USER, TestConfig.ADMIN_PASSWORD))
        self.assertEqual(resp.status_code, 200)


class TestHealthAndPolicies(ApiTestCase):
    def test_health(self):
        resp = self.client.get("/health")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json()["status"], "armed")

    def test_list_policies_filtered_by_domain(self):
        resp = self.client.get("/policies?domain=access")
        names = {p["name"] for p in resp.get_json()}
        self.assertIn("Allow employees on internal resources", names)
        self.assertNotIn("Capture on high-confidence beaconing", names)


class TestEventsAndChain(ApiTestCase):
    def test_fire_event_quarantines_and_chains(self):
        resp = self.client.post("/events", json={
            "domain": "threat", "payload": {"agent": {"tool_calls_per_min": 340}},
        })
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json()["action"], "quarantine")

        chain = self.client.get("/audit-chain").get_json()
        self.assertEqual(len(chain), 1)
        self.assertEqual(chain[0]["action"], "quarantine")

        q = self.client.get("/quarantine").get_json()
        self.assertEqual(len(q), 1)
        self.assertEqual(q[0]["status"], "quarantined")

    def test_verify_chain_ok_then_detects_rewrite(self):
        self.client.post("/events", json={
            "domain": "access",
            "payload": {"actor": {"role": "contractor"}, "resource": {"classification": "restricted"}},
        })
        self.assertTrue(self.client.post("/audit-chain/verify").get_json()["verified"])

        # Directly corrupt a block's content without touching its stored
        # hash — the same "rewritten record" the console demo simulates.
        with self.app.app_context():
            conn = arachnode_db.get_db()
            conn.execute("UPDATE audit_blocks SET explanation = 'nothing to see here' WHERE idx = 1")
            conn.commit()

        result = self.client.post("/audit-chain/verify").get_json()
        self.assertFalse(result["verified"])
        self.assertEqual(result["broken_at"], 1)


class TestDiscernmentGate(ApiTestCase):
    def test_release_from_quarantine_requires_discernment_key(self):
        self.client.post("/events", json={
            "domain": "threat", "payload": {"agent": {"tool_calls_per_min": 340}},
        })
        item_id = self.client.get("/quarantine").get_json()[0]["id"]

        denied = self.client.post(f"/quarantine/{item_id}/release")
        self.assertEqual(denied.status_code, 403)

        allowed = self.client.post(
            f"/quarantine/{item_id}/release",
            headers={"X-Discernment-Key": "test-discernment-key"},
        )
        self.assertEqual(allowed.status_code, 200)
        self.assertEqual(allowed.get_json()["status"], "released")

    def test_setting_policy_to_allow_requires_discernment_key(self):
        denied = self.client.patch("/policies/p-access-deny", json={"action": "allow"})
        self.assertEqual(denied.status_code, 403)

        allowed = self.client.patch(
            "/policies/p-access-deny", json={"action": "allow"},
            headers={"X-Discernment-Key": "test-discernment-key"},
        )
        self.assertEqual(allowed.status_code, 200)
        self.assertEqual(allowed.get_json()["action"], "allow")

    def test_tightening_a_policy_needs_no_discernment_key(self):
        resp = self.client.patch("/policies/p-access-allow", json={"action": "deny"})
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json()["action"], "deny")


class TestPolicyCRUD(ApiTestCase):
    NEW_DENY_POLICY = {
        "id": "p-test-deny", "name": "Deny interns everywhere", "domain": "access",
        "priority": 1, "action": "deny",
        "conditions": [{"field": "actor.role", "operator": "eq", "value": "intern"}],
    }
    NEW_ALLOW_POLICY = {
        "id": "p-test-allow", "name": "Allow auditors read access", "domain": "access",
        "priority": 2, "action": "allow",
        "conditions": [{"field": "actor.role", "operator": "eq", "value": "auditor"}],
    }

    def test_create_tightening_policy_needs_no_key(self):
        resp = self.client.post("/policies", json=self.NEW_DENY_POLICY)
        self.assertEqual(resp.status_code, 201)
        self.assertEqual(resp.get_json()["id"], "p-test-deny")

        # And it's immediately live in evaluate().
        fired = self.client.post("/events", json={
            "domain": "access", "payload": {"actor": {"role": "intern"}},
        })
        self.assertEqual(fired.get_json()["action"], "deny")
        self.assertEqual(fired.get_json()["policy_id"], "p-test-deny")

    def test_create_enabled_allow_policy_requires_discernment_key(self):
        denied = self.client.post("/policies", json=self.NEW_ALLOW_POLICY)
        self.assertEqual(denied.status_code, 403)

        allowed = self.client.post(
            "/policies", json=self.NEW_ALLOW_POLICY,
            headers={"X-Discernment-Key": "test-discernment-key"},
        )
        self.assertEqual(allowed.status_code, 201)

    def test_create_disabled_allow_policy_needs_no_key(self):
        """Not yet in effect -> not yet a loosening."""
        spec = {**self.NEW_ALLOW_POLICY, "enabled": False}
        resp = self.client.post("/policies", json=spec)
        self.assertEqual(resp.status_code, 201)
        self.assertFalse(resp.get_json()["enabled"])

    def test_create_duplicate_id_conflicts(self):
        self.client.post("/policies", json=self.NEW_DENY_POLICY)
        dup = self.client.post("/policies", json=self.NEW_DENY_POLICY)
        self.assertEqual(dup.status_code, 409)

    def test_create_rejects_malformed_policy(self):
        bad = {**self.NEW_DENY_POLICY, "id": "p-bad", "domain": "not-a-real-domain"}
        resp = self.client.post("/policies", json=bad)
        self.assertEqual(resp.status_code, 400)

        bad_condition = {**self.NEW_DENY_POLICY, "id": "p-bad-2",
                         "conditions": [{"field": "x", "operator": "not_a_real_op", "value": 1}]}
        resp2 = self.client.post("/policies", json=bad_condition)
        self.assertEqual(resp2.status_code, 400)

    def test_create_records_audit_block(self):
        self.client.post("/policies", json=self.NEW_DENY_POLICY)
        chain = self.client.get("/audit-chain").get_json()
        self.assertEqual(chain[-1]["kind"], "policy_change")
        self.assertIn("created", chain[-1]["explanation"])

    def test_delete_deny_policy_requires_discernment_key(self):
        """Deleting a restriction loosens enforcement."""
        denied = self.client.delete("/policies/p-access-deny")
        self.assertEqual(denied.status_code, 403)

        allowed = self.client.delete(
            "/policies/p-access-deny", headers={"X-Discernment-Key": "test-discernment-key"},
        )
        self.assertEqual(allowed.status_code, 204)
        ids = {p["id"] for p in self.client.get("/policies").get_json()}
        self.assertNotIn("p-access-deny", ids)

    def test_delete_allow_policy_needs_no_key(self):
        """Deleting a permission tightens enforcement."""
        resp = self.client.delete("/policies/p-access-allow")
        self.assertEqual(resp.status_code, 204)

        ids = {p["id"] for p in self.client.get("/policies").get_json()}
        self.assertNotIn("p-access-allow", ids)

    def test_delete_nonexistent_policy_404s(self):
        resp = self.client.delete("/policies/does-not-exist")
        self.assertEqual(resp.status_code, 404)

    def test_delete_records_audit_block(self):
        self.client.delete("/policies/p-access-allow")
        chain = self.client.get("/audit-chain").get_json()
        self.assertEqual(chain[-1]["kind"], "policy_change")
        self.assertIn("deleted", chain[-1]["explanation"])

    def test_deleted_restrictive_policy_no_longer_fires(self):
        self.client.delete(
            "/policies/p-access-deny", headers={"X-Discernment-Key": "test-discernment-key"},
        )
        fired = self.client.post("/events", json={
            "domain": "access",
            "payload": {"actor": {"role": "contractor"}, "resource": {"classification": "restricted"}},
        })
        # p-access-deny is gone -> no policy matches -> falls to domain default
        self.assertEqual(fired.get_json()["action"], "deny")  # access domain default is itself deny
        self.assertIsNone(fired.get_json()["policy_id"])


class TestRogueEditDetection(ApiTestCase):
    def test_rogue_edit_is_caught_on_next_evaluation(self):
        resp = self.client.post("/admin/rogue-edit/p-access-allow", json={"action": "deny"})
        self.assertEqual(resp.status_code, 200)

        fired = self.client.post("/events", json={
            "domain": "access",
            "payload": {"actor": {"role": "employee"}, "resource": {"classification": "internal"}},
        })
        body = fired.get_json()
        self.assertIn("p-access-allow", body["tampered"])
        self.assertEqual(body["action"], "deny")  # falls back to domain default
        self.assertEqual(len(body["alerts"]), 1)

        chain = self.client.get("/audit-chain").get_json()
        self.assertEqual(chain[-1]["kind"], "alert")


if __name__ == "__main__":
    unittest.main()
