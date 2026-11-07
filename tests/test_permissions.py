import unittest

from modules.rogue_app_permission_analyzer import analyze_permissions


class PermissionAnalyzerTests(unittest.TestCase):
    def test_permission_matching_is_case_insensitive(self):
        result = analyze_permissions(["camera", "read_sms"])
        self.assertEqual(result["status"], "MEDIUM")
        self.assertEqual(
            [item["permission"] for item in result["risky"]],
            ["CAMERA", "READ_SMS"],
        )

    def test_three_risky_permissions_raise_high_status(self):
        result = analyze_permissions(["CAMERA", "RECORD_AUDIO", "READ_CONTACTS"])
        self.assertEqual(result["status"], "HIGH")
        self.assertEqual(len(result["risky"]), 3)

    def test_unknown_and_empty_permissions_are_handled(self):
        result = analyze_permissions(["", "INTERNET", "  "])
        self.assertEqual(result["status"], "SAFE")
        self.assertEqual(result["safe"], ["INTERNET"])
        self.assertEqual(result["risky"], [])


if __name__ == "__main__":
    unittest.main()
