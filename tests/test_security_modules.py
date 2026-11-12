import unittest

from modules.cyber_risk_dashboard import build_dashboard
from modules.digital_footprint_leak_checker import check_digital_footprint
from modules.public_wifi_risk_indicator import wifi_risk
from modules.rogue_app_permission_analyzer import analyze_permissions


class SecurityModuleTests(unittest.TestCase):
    def test_footprint_matching_is_case_insensitive(self):
        result = check_digital_footprint("Found on PASTEBIN")
        self.assertEqual(result["status"], "HIGH")
        self.assertIn("pastebin", result["keywords"])

    def test_footprint_safe_result_has_empty_keywords(self):
        result = check_digital_footprint("ordinary profile description")
        self.assertEqual(result["status"], "SAFE")
        self.assertEqual(result["keywords"], [])

    def test_unknown_wifi_encryption_is_not_reported_safe(self):
        result = wifi_risk("UNKNOWN-SECURITY", False)
        self.assertEqual(result["status"], "MEDIUM")
        self.assertTrue(any("Unknown encryption" in flag for flag in result["flags"]))

    def test_open_public_wifi_is_high_risk(self):
        result = wifi_risk("OPEN", True)
        self.assertEqual(result["status"], "HIGH")

    def test_permission_matching_ignores_case_and_whitespace(self):
        result = analyze_permissions([" read_sms ", "camera"])
        self.assertEqual(result["status"], "MEDIUM")
        self.assertEqual(
            {item["permission"] for item in result["risky"]},
            {"READ_SMS", "CAMERA"},
        )

    def test_dashboard_counts_high_and_medium_findings(self):
        result = build_dashboard({
            "one": {"status": "HIGH", "message": "high finding"},
            "two": {"status": "MEDIUM", "message": "medium finding"},
            "three": {"status": "SAFE", "message": "clear"},
        })
        self.assertEqual(result["score"], 3)
        self.assertEqual(result["max_score"], 6)
        self.assertEqual(result["overall"], "MEDIUM")

    def test_duplicate_permissions_are_counted_only_once(self):
        result = analyze_permissions(["CAMERA", "camera", " READ_SMS "])
        self.assertEqual(len(result["risky"]), 2)
        self.assertEqual(result["status"], "MEDIUM")


if __name__ == "__main__":
    unittest.main()
