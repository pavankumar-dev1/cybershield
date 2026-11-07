import unittest

from modules.password_strength_analyzer import analyze_password


class PasswordStrengthTests(unittest.TestCase):
    def test_password_with_all_character_classes_scores_strong(self):
        result = analyze_password("Abcdef1!")
        self.assertEqual(result["status"], "STRONG")
        self.assertEqual(result["score"], 5)
        self.assertEqual(result["max_score"], 5)
        self.assertEqual(result["tips"], [])

    def test_short_lowercase_password_reports_missing_requirements(self):
        result = analyze_password("abcdefg")
        self.assertEqual(result["status"], "WEAK")
        self.assertEqual(result["score"], 1)
        self.assertIn("Use at least 8 characters", result["tips"])
        self.assertIn("Add uppercase letters", result["tips"])
        self.assertIn("Add numbers", result["tips"])
        self.assertIn("Add special characters (!@#$...)", result["tips"])

    def test_empty_password_is_weak_and_returns_all_tips(self):
        result = analyze_password("")
        self.assertEqual(result["status"], "WEAK")
        self.assertEqual(result["score"], 0)
        self.assertEqual(len(result["tips"]), 5)


if __name__ == "__main__":
    unittest.main()
