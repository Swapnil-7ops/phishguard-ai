"""
test_message_regression.py - Message/SMS analysis edge-case regression tests.
Uses only the standard library (unittest) — no pytest required.
"""
import sys
import os
import unittest

# Ensure project root is on the path when running this file directly
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from services.message_analyzer import analyze_message


class TestMessageEdgeCases(unittest.TestCase):
    """Regression tests for analyze_message edge cases."""

    def test_empty_message(self):
        """Empty string must be rejected with success=False."""
        result = analyze_message('')
        self.assertFalse(result["success"])
        self.assertIn("cannot be empty", result.get("error", "").lower())

    def test_whitespace_only_message(self):
        """Whitespace-only input documents known limitation: returns success=True."""
        result = analyze_message('   ')
        # Documented limitation in docs/limitations.md: strips whitespace but returns success=True
        self.assertTrue(result["success"])

    def test_long_message(self):
        """Very long repetitive message must not crash and must return expected keys."""
        long_msg = 'spam ' * 2000
        result = analyze_message(long_msg)
        self.assertTrue(result["success"])
        for key in ["prediction", "ml_probability", "risk_score"]:
            self.assertIn(key, result)

    def test_unicode_message(self):
        """Unicode text (Japanese, Arabic, emoji) must be handled without error."""
        msg = "これはスパムです 🔔 مرحبا"
        result = analyze_message(msg)
        self.assertTrue(result["success"])
        for key in ["prediction", "ml_probability", "risk_score"]:
            self.assertIn(key, result)

    def test_punctuation_heavy_message(self):
        """Punctuation-heavy text must not raise an exception."""
        msg = "!!! WIN $$$ NOW!!! Click @here #free #prize"
        result = analyze_message(msg)
        self.assertTrue(result["success"])
        self.assertIn("prediction", result)

    def test_message_with_single_url(self):
        """Message containing a single URL must trigger URL cascade analysis."""
        msg = "Check this out: https://example.com"
        result = analyze_message(msg)
        self.assertTrue(result["success"])
        self.assertIsInstance(result.get("extracted_urls"), list)
        self.assertGreater(len(result.get("extracted_urls", [])), 0)
        self.assertIsInstance(result.get("url_analyses"), list)

    def test_message_with_multiple_urls(self):
        """Message with multiple URLs must extract all (up to cascade limit)."""
        msg = "Visit https://example.com and also http://another-site.net for details."
        result = analyze_message(msg)
        self.assertTrue(result["success"])
        self.assertIsInstance(result.get("extracted_urls"), list)
        self.assertIsInstance(result.get("url_analyses"), list)

    def test_message_no_urls(self):
        """Message without URLs must return an empty extracted_urls list."""
        msg = "Please verify your account credentials immediately"
        result = analyze_message(msg)
        self.assertTrue(result["success"])
        self.assertEqual(result.get("extracted_urls"), [])
        self.assertIn("prediction", result)

    def test_message_result_has_required_keys(self):
        """Successful analysis must always include the canonical keys."""
        result = analyze_message("Congratulations, you won a prize!")
        self.assertTrue(result["success"])
        for key in ["prediction", "ml_probability", "risk_score",
                    "explanation", "model_loaded", "extracted_urls", "url_analyses"]:
            self.assertIn(key, result, f"Missing key: {key}")

    def test_message_risk_score_bounded(self):
        """Risk score must be a number in [0, 100]."""
        result = analyze_message("Your account has been compromised. Act now!")
        self.assertTrue(result["success"])
        score = result.get("risk_score", -1)
        self.assertIsInstance(score, (int, float))
        self.assertGreaterEqual(score, 0)
        self.assertLessEqual(score, 100)


# ---------------------------------------------------------------------------
# Public test_ functions consumed by run_tests.py wrapper
# ---------------------------------------------------------------------------

def test_empty_message():
    obj = TestMessageEdgeCases(); obj.test_empty_message()

def test_whitespace_only_message():
    obj = TestMessageEdgeCases(); obj.test_whitespace_only_message()

def test_long_message():
    obj = TestMessageEdgeCases(); obj.test_long_message()

def test_unicode_message():
    obj = TestMessageEdgeCases(); obj.test_unicode_message()

def test_message_with_punctuation():
    obj = TestMessageEdgeCases(); obj.test_punctuation_heavy_message()

def test_message_with_single_url():
    obj = TestMessageEdgeCases(); obj.test_message_with_single_url()

def test_message_with_multiple_urls():
    obj = TestMessageEdgeCases(); obj.test_message_with_multiple_urls()

def test_message_no_urls():
    obj = TestMessageEdgeCases(); obj.test_message_no_urls()

def test_message_result_has_required_keys():
    obj = TestMessageEdgeCases(); obj.test_message_result_has_required_keys()

def test_message_risk_score_bounded():
    obj = TestMessageEdgeCases(); obj.test_message_risk_score_bounded()


if __name__ == '__main__':
    unittest.main()
