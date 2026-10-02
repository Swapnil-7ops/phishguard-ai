"""
test_model_loading_failure.py - Tests that graceful degradation works correctly
when model files are missing or inaccessible.

Uses only the standard library (unittest + unittest.mock) — no pytest required.
"""
import sys
import os
import unittest
import importlib
from unittest.mock import patch, MagicMock
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))


class TestURLModelLoadingFailure(unittest.TestCase):
    """Verify that analyze_url degrades gracefully when the URL model is missing."""

    def _analyze_with_missing_model(self):
        """Run analyze_url with load_model patched to return (None, None, None)."""
        import services.url_analyzer as ua
        # Patch load_model to simulate missing file
        with patch.object(ua, 'load_model', return_value=(None, None, None)):
            # Also clear the module-level cache so the patch takes effect
            ua._model = None
            ua._feature_names = None
            ua._label_config = None
            result = ua.analyze_url('http://example.com')
        return result

    def test_url_model_missing_returns_success_dict(self):
        """When model is absent, analyze_url must still return a result dict (no exception)."""
        result = self._analyze_with_missing_model()
        self.assertIsInstance(result, dict)

    def test_url_model_missing_model_loaded_false(self):
        """When model is absent, model_loaded must be False."""
        result = self._analyze_with_missing_model()
        self.assertFalse(result.get("model_loaded", True),
                         "Expected model_loaded=False when model file is missing")

    def test_url_model_missing_has_risk_score(self):
        """Even without ML model, risk_score must be present (heuristic fallback)."""
        result = self._analyze_with_missing_model()
        # success may be True (heuristic-only mode) or False depending on implementation
        # but the result must contain risk_score if success is True
        if result.get("success"):
            self.assertIn("risk_score", result)

    def test_url_model_missing_no_exception_for_dangerous_scheme(self):
        """Dangerous-scheme rejection must still work without a model."""
        import services.url_analyzer as ua
        with patch.object(ua, 'load_model', return_value=(None, None, None)):
            result = ua.analyze_url('javascript:evil()')
        self.assertFalse(result.get("success", True))
        self.assertIn("error", result)


class TestTextModelLoadingFailure(unittest.TestCase):
    """Verify that analyze_message degrades gracefully when text models are missing."""

    def _analyze_with_missing_text_model(self, text="Win a free prize now!"):
        """Run analyze_message with load_text_models patched to return (None, None)."""
        import services.message_analyzer as ma
        with patch.object(ma, 'load_text_models', return_value=(None, None)):
            # Clear module-level cache
            ma._text_clf = None
            ma._text_vec = None
            result = ma.analyze_message(text)
        return result

    def test_text_model_missing_returns_dict(self):
        """With text model absent, analyze_message must return a dict without raising."""
        result = self._analyze_with_missing_text_model()
        self.assertIsInstance(result, dict)

    def test_text_model_missing_model_loaded_false(self):
        """model_loaded must be False when text model files are absent."""
        result = self._analyze_with_missing_text_model()
        self.assertFalse(result.get("model_loaded", True),
                         "Expected model_loaded=False when text model is missing")

    def test_text_model_missing_success_field_present(self):
        """success field must always be present in the response."""
        result = self._analyze_with_missing_text_model()
        self.assertIn("success", result)

    def test_text_model_missing_ml_probability_is_none(self):
        """ml_probability must be None when model is offline."""
        result = self._analyze_with_missing_text_model()
        if result.get("success"):
            # When falling back to heuristics, ml_probability should be None or absent
            ml_prob = result.get("ml_probability")
            self.assertIsNone(ml_prob,
                              f"Expected ml_probability=None in fallback mode, got {ml_prob}")

    def test_text_model_missing_empty_input_still_rejected(self):
        """Empty input validation must happen before model loading."""
        import services.message_analyzer as ma
        with patch.object(ma, 'load_text_models', return_value=(None, None)):
            result = ma.analyze_message('')
        self.assertFalse(result.get("success", True))
        self.assertIn("error", result)


# ---------------------------------------------------------------------------
# Public test_ functions consumed by run_tests.py wrapper
# ---------------------------------------------------------------------------

def test_url_model_missing_returns_success_dict():
    obj = TestURLModelLoadingFailure(); obj.test_url_model_missing_returns_success_dict()

def test_url_model_missing_model_loaded_false():
    obj = TestURLModelLoadingFailure(); obj.test_url_model_missing_model_loaded_false()

def test_url_model_missing_has_risk_score():
    obj = TestURLModelLoadingFailure(); obj.test_url_model_missing_has_risk_score()

def test_url_model_missing_dangerous_scheme_still_rejected():
    obj = TestURLModelLoadingFailure(); obj.test_url_model_missing_no_exception_for_dangerous_scheme()

def test_text_model_missing_returns_dict():
    obj = TestTextModelLoadingFailure(); obj.test_text_model_missing_returns_dict()

def test_text_model_missing_model_loaded_false():
    obj = TestTextModelLoadingFailure(); obj.test_text_model_missing_model_loaded_false()

def test_text_model_missing_success_field_present():
    obj = TestTextModelLoadingFailure(); obj.test_text_model_missing_success_field_present()

def test_text_model_missing_ml_probability_is_none():
    obj = TestTextModelLoadingFailure(); obj.test_text_model_missing_ml_probability_is_none()

def test_text_model_missing_empty_input_still_rejected():
    obj = TestTextModelLoadingFailure(); obj.test_text_model_missing_empty_input_still_rejected()


if __name__ == '__main__':
    unittest.main()

