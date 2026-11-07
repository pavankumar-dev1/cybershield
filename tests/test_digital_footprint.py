import unittest

from modules.digital_footprint_leak_checker import check_digital_footprint


class DigitalFootprintTests(unittest.TestCase):
    def test_known_leak_keyword_is_reported(self):
        result = check_digital_footprint("Possible BREACH report")
        self.assertEqual(result["status"], "HIGH")
        self.assertEqual(result["keywords"], ["breach"])

    def test_multiple_keywords_are_returned_once_in_configured_order(self):
        result = check_digital_footprint("pastebin dump and exposed data")
        self.assertEqual(result["keywords"], ["pastebin", "dump", "exposed"])

    def test_text_without_known_keywords_is_not_flagged(self):
        result = check_digital_footprint("A regular public profile")
        self.assertEqual(result["status"], "SAFE")
        self.assertEqual(result["keywords"], [])


if __name__ == "__main__":
    unittest.main()
