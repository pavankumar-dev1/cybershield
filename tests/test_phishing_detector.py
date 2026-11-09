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

    def test_suspicious_tld_on_hostname_is_flagged(self):
        result = detect_phishing("https://example.xyz")
        self.assertIn("Suspicious domain extension: .xyz", result["flags"])
        self.assertEqual(result["status"], "MEDIUM")

    def test_suspicious_tld_in_path_is_not_treated_as_domain_tld(self):
        result = detect_phishing("https://example.com/download.xyz")
        self.assertEqual(result["status"], "SAFE")
        self.assertFalse(any("domain extension" in flag for flag in result["flags"]))

    def test_suspicious_tld_in_query_is_not_treated_as_domain_tld(self):
        result = detect_phishing("https://example.com/search?q=.xyz")
        self.assertEqual(result["status"], "SAFE")
        self.assertFalse(any("domain extension" in flag for flag in result["flags"]))

    def test_suspicious_tld_inside_longer_domain_suffix_is_not_flagged(self):
        result = detect_phishing("https://example.xyz.evil.com")
        self.assertEqual(result["status"], "SAFE")
        self.assertFalse(any("domain extension" in flag for flag in result["flags"]))

    def test_valid_ipv6_literal_is_flagged(self):
        result = detect_phishing("https://[2001:db8::1]/")
        self.assertEqual(result["status"], "MEDIUM")
        self.assertIn("URL uses IP address instead of domain", result["flags"])


if __name__ == "__main__":
    unittest.main()
