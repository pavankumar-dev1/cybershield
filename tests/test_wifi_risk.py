import unittest

from modules.public_wifi_risk_indicator import wifi_risk


class WifiRiskTests(unittest.TestCase):
    def test_open_public_network_is_high_risk(self):
        result = wifi_risk("OPEN", True)
        self.assertEqual(result["status"], "HIGH")
        self.assertTrue(result["is_public"])
        self.assertIn("No encryption — traffic is fully exposed", result["flags"])

    def test_wpa3_private_network_is_reported_safe(self):
        result = wifi_risk(" WPA3 ", False)
        self.assertEqual(result["status"], "SAFE")
        self.assertEqual(result["encryption"], "WPA3")
        self.assertEqual(result["tips"], [])

    def test_wep_private_network_is_medium_risk(self):
        result = wifi_risk("WEP", False)
        self.assertEqual(result["status"], "MEDIUM")
        self.assertTrue(result["tips"])


if __name__ == "__main__":
    unittest.main()
