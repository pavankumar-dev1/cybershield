import unittest

from modules.cyber_risk_dashboard import build_dashboard


class CyberRiskDashboardTests(unittest.TestCase):
    def test_empty_results_produce_zero_score(self):
        result = build_dashboard({})
        self.assertEqual(result["overall"], "SAFE")
        self.assertEqual(result["score"], 0)
        self.assertEqual(result["max_score"], 0)
        self.assertEqual(result["breakdown"], {})

    def test_high_risk_module_is_reflected_in_score_and_breakdown(self):
        result = build_dashboard({
            "WiFi Risk": {"status": "HIGH", "message": "Open public network"}
        })
        self.assertEqual(result["overall"], "HIGH")
        self.assertEqual(result["score"], 2)
        self.assertEqual(result["max_score"], 2)
        self.assertEqual(result["breakdown"]["WiFi Risk"]["status"], "HIGH")

    def test_safe_modules_keep_dashboard_safe(self):
        result = build_dashboard({
            "Password": {"status": "SAFE", "message": "No flags"},
            "WiFi": {"status": "SAFE", "message": "Protected"},
        })
        self.assertEqual(result["overall"], "SAFE")
        self.assertEqual(result["score"], 0)


if __name__ == "__main__":
    unittest.main()
