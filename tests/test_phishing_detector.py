import unittest

from modules.phishing_link_qr_detector import detect_phishing


class PhishingDetectorTests(unittest.TestCase):
    def test_plain_https_domain_has_no_current_indicators(self):
        result = detect_phishing("https://example.com")
        self.assertEqual(result["status"], "SAFE")
        self.assertEqual(result["score"], 0)
        self.assertEqual(result["flags"], [])

    def test_http_url_is_flagged_as_medium_risk(self):
        result = detect_phishing("http://example.com")
        self.assertEqual(result["status"], "MEDIUM")
        self.assertIn("Uses HTTP (not secure)", result["flags"])

    def test_ip_address_and_suspicious_terms_increase_risk(self):
        result = detect_phishing("http://192.168.1.10/login")
        self.assertEqual(result["status"], "HIGH")
        self.assertTrue(any("IP address" in flag for flag in result["flags"]))
        self.assertTrue(any("Suspicious words" in flag for flag in result["flags"]))


if __name__ == "__main__":
    unittest.main()
