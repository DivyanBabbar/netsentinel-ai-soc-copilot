"""API tests for the endpoints, run through FastAPI's TestClient (no network, no model call).

Needs fastapi and httpx (pip install -r requirements.txt httpx); skipped if they are missing.
"""
import os
import unittest
from unittest import mock

os.environ.setdefault("PROTECTED_TARGETS", "10.0.0.1")

try:
    from fastapi.testclient import TestClient

    from netsentinel.api import app
    from netsentinel.triage import TriageError
except ImportError:  # pragma: no cover
    app = None


@unittest.skipIf(app is None, "fastapi/httpx not installed")
class ApiTests(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)

    def post_action(self, action_type, target, approved=True):
        return self.client.post("/actions/execute", json={"approved": approved, "action": {"type": action_type, "target": target, "reason": "test"}})

    def test_health_reports_knowledge_base_and_dry_run(self):
        body = self.client.get("/health").json()
        self.assertEqual(body["status"], "ok")
        self.assertEqual(body["techniques_loaded"], 20)
        self.assertTrue(body["dry_run"])

    def test_action_without_approval_is_refused(self):
        self.assertEqual(self.post_action("block_ip", "203.0.113.9", approved=False).status_code, 400)

    def test_approved_action_is_dry_run_by_default(self):
        body = self.post_action("block_ip", "203.0.113.9").json()
        self.assertEqual(body["status"], "dry_run")

    def test_protected_target_is_rejected(self):
        self.assertEqual(self.post_action("block_ip", "10.0.0.1").json()["status"], "rejected")

    def test_unknown_action_type_is_rejected(self):
        self.assertEqual(self.post_action("rm_rf", "x").json()["status"], "rejected")

    def test_invalid_ip_is_rejected(self):
        self.assertEqual(self.post_action("block_ip", "not-an-ip").json()["status"], "rejected")

    def test_empty_logs_fail_validation(self):
        self.assertEqual(self.client.post("/triage", json={"logs": ""}).status_code, 422)

    def test_triage_without_credentials_is_503_not_500(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            response = self.client.post("/triage", json={"logs": "Failed password for root from 203.0.113.9"})
        self.assertEqual(response.status_code, 503)
        self.assertIn("model unavailable", response.json()["detail"])

    def test_rejected_model_output_is_502(self):
        with mock.patch("netsentinel.api.run_triage", side_effect=TriageError("bad json")):
            response = self.client.post("/triage", json={"logs": "x"})
        self.assertEqual(response.status_code, 502)


if __name__ == "__main__":
    unittest.main()
