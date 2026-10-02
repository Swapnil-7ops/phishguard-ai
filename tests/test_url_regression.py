"""
test_url_regression.py - URL validation and analysis edge-case regression tests.
Uses only the standard library (unittest) — no pytest required.
"""
import sys
import os
import unittest

# Ensure project root is on the path when running this file directly
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from services.url_analyzer import validate_and_normalize_url, analyze_url


class TestURLValidation(unittest.TestCase):
    """Regression tests for validate_and_normalize_url edge cases."""

    def test_validate_scheme_less_url(self):
        """Scheme-less input must be normalized to http://."""
        res = validate_and_normalize_url('google.com')
        self.assertTrue(res["valid"])
        self.assertTrue(res["normalized_url"].startswith('http://'))

    def test_validate_http_scheme(self):
        """http:// URLs must be accepted unchanged."""
        res = validate_and_normalize_url('http://example.com')
        self.assertTrue(res["valid"])
        self.assertEqual(res["normalized_url"], 'http://example.com')

    def test_validate_https_scheme(self):
        """https:// URLs must be accepted unchanged."""
        res = validate_and_normalize_url('https://example.com')
        self.assertTrue(res["valid"])
        self.assertEqual(res["normalized_url"], 'https://example.com')

    def test_invalid_scheme_rejection(self):
        """javascript: scheme must be rejected."""
        res = validate_and_normalize_url('javascript:alert(1)')
        self.assertFalse(res["valid"])
        self.assertIn("Unsupported or unsafe protocol", res.get("error", ""))

    def test_data_scheme_rejection(self):
        """data: scheme must be rejected."""
        res = validate_and_normalize_url('data:text/html,<h1>hi</h1>')
        self.assertFalse(res["valid"])

    def test_file_scheme_rejection(self):
        """file: scheme must be rejected."""
        res = validate_and_normalize_url('file:///etc/passwd')
        self.assertFalse(res["valid"])

    def test_empty_input(self):
        """Empty string must be rejected with an appropriate error message."""
        res = validate_and_normalize_url('')
        self.assertFalse(res["valid"])
        self.assertIn("cannot be empty", res.get("error", "").lower())

    def test_whitespace_only_input(self):
        """Whitespace-only string must be rejected."""
        res = validate_and_normalize_url('   ')
        self.assertFalse(res["valid"])

    def test_very_long_url(self):
        """URL exceeding 2048 characters must be rejected."""
        long_url = 'http://' + 'a' * 2100 + '.com'
        res = validate_and_normalize_url(long_url)
        self.assertFalse(res["valid"])
        self.assertIn("exceeds", res.get("error", "").lower())


class TestAnalyzeURL(unittest.TestCase):
    """Regression tests for analyze_url edge cases."""

    def test_analyze_url_with_invalid_scheme(self):
        """analyze_url must return success=False for dangerous scheme."""
        result = analyze_url('javascript:alert(1)')
        self.assertFalse(result["success"])
        self.assertIn("Unsupported", result.get("error", ""))

    def test_analyze_url_missing_scheme(self):
        """analyze_url must prepend http:// for scheme-less input and succeed."""
        result = analyze_url('example.com')
        self.assertTrue(result["success"])
        for key in ["prediction", "ml_probability_estimate", "risk_score"]:
            self.assertIn(key, result)

    def test_analyze_url_normal_https(self):
        """analyze_url with a normal https URL must succeed and return expected keys."""
        result = analyze_url('https://example.com')
        self.assertTrue(result["success"])
        for key in ["prediction", "risk_score", "explanation"]:
            self.assertIn(key, result)

    def test_analyze_url_unicode_domain(self):
        """analyze_url must handle Unicode domain names without crashing."""
        result = analyze_url('http://пример.испытание')
        # May succeed or fail validation, but must not raise an unhandled exception
        self.assertIsInstance(result, dict)
        self.assertIn("success", result)


# ---------------------------------------------------------------------------
# Standalone runner helpers (used by run_tests.py wrapper style)
# ---------------------------------------------------------------------------

def _run_test(fn_name, fn):
    try:
        fn()
        print(f"  [PASS] {fn_name}")
        return True
    except Exception as e:
        print(f"  [FAIL] {fn_name} -> {e}")
        return False


def _collect(cls):
    obj = cls()
    return [(n, getattr(obj, n)) for n in dir(obj) if n.startswith('test_')]


# Public test_ functions consumed by run_tests.py
def test_validate_scheme_less_url():
    obj = TestURLValidation(); obj.test_validate_scheme_less_url()

def test_validate_http_scheme():
    obj = TestURLValidation(); obj.test_validate_http_scheme()

def test_validate_https_scheme():
    obj = TestURLValidation(); obj.test_validate_https_scheme()

def test_invalid_scheme_rejection():
    obj = TestURLValidation(); obj.test_invalid_scheme_rejection()

def test_data_scheme_rejection():
    obj = TestURLValidation(); obj.test_data_scheme_rejection()

def test_file_scheme_rejection():
    obj = TestURLValidation(); obj.test_file_scheme_rejection()

def test_empty_input():
    obj = TestURLValidation(); obj.test_empty_input()

def test_whitespace_only_input():
    obj = TestURLValidation(); obj.test_whitespace_only_input()

def test_very_long_url():
    obj = TestURLValidation(); obj.test_very_long_url()

def test_analyze_url_with_invalid_scheme():
    obj = TestAnalyzeURL(); obj.test_analyze_url_with_invalid_scheme()

def test_analyze_url_missing_scheme():
    obj = TestAnalyzeURL(); obj.test_analyze_url_missing_scheme()

def test_analyze_url_normal_https():
    obj = TestAnalyzeURL(); obj.test_analyze_url_normal_https()

def test_analyze_url_unicode_domain():
    obj = TestAnalyzeURL(); obj.test_analyze_url_unicode_domain()


if __name__ == '__main__':
    unittest.main()
