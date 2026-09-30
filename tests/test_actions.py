import unittest

from netsentinel.actions import execute_action, validate_action


class ActionTests(unittest.TestCase):
    def test_valid_block_ip(self):
        ok, cleaned = validate_action({"type": "block_ip", "target": "203.0.113.45", "reason": "brute force"})
        self.assertTrue(ok)
        self.assertEqual(cleaned["target"], "203.0.113.45")

    def test_rejects_unknown_action_type(self):
        ok, _ = validate_action({"type": "run_shell", "target": "rm -rf /"})
        self.assertFalse(ok)

    def test_rejects_loopback_and_garbage_ip(self):
        self.assertFalse(validate_action({"type": "block_ip", "target": "127.0.0.1"})[0])
        self.assertFalse(validate_action({"type": "block_ip", "target": "1.2.3.4; reboot"})[0])

    def test_rejects_protected_target(self):
        ok, reason = validate_action({"type": "block_ip", "target": "10.0.0.1"}, protected_targets=("10.0.0.1",))
        self.assertFalse(ok)
        self.assertIn("protected", reason)

    def test_rejects_bad_hostname_and_username(self):
        self.assertFalse(validate_action({"type": "isolate_host", "target": "web01; rm -rf /"})[0])
        self.assertFalse(validate_action({"type": "disable_account", "target": "root user"})[0])

    def test_rejects_newline_in_ticket_target(self):
        self.assertFalse(validate_action({"type": "open_ticket", "target": "line1\nline2"})[0])

    def test_high_impact_flag(self):
        ok, cleaned = validate_action({"type": "isolate_host", "target": "web01"})
        self.assertTrue(ok)
        self.assertTrue(cleaned["high_impact"])

    def test_execute_is_dry_run_by_default(self):
        result = execute_action({"type": "block_ip", "target": "203.0.113.45", "reason": "x"})
        self.assertEqual(result["status"], "dry_run")

    def test_execute_revalidates(self):
        result = execute_action({"type": "block_ip", "target": "not-an-ip"})
        self.assertEqual(result["status"], "rejected")

    def test_live_block_ip_is_not_implemented(self):
        result = execute_action({"type": "block_ip", "target": "203.0.113.45"}, dry_run=False)
        self.assertEqual(result["status"], "not_implemented")


if __name__ == "__main__":
    unittest.main()
