"""
test_explanation.py - Phase 9 Integration + Unit Tests for Explainability Layer

Tests the new structured explanation builder by:
  1. Calling actual Flask endpoints with test_client() (integration).
  2. Calling explanation builder functions directly (unit).

Baseline: 93 tests.
This file adds the Phase 9 tests on top.

Rules:
  - Never re-calculate risk scores in these tests.
  - Verify explanation data comes from actual backend results.
  - HTTPS must NOT be described as proof of legitimacy.
  - Global feature importance must be labeled as global, not per-sample.
  - No fabricated indicators allowed in results.
"""
import sys
import json
from pathlib import Path
from typing import Any, Dict

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))

from app import create_app


# ── Helpers ────────────────────────────────────────────────────────────────

def get_client():
    app = create_app()
    app.config['TESTING'] = True
    return app.test_client()


def post_url(client, url: str) -> Dict[str, Any]:
    """POST a URL to the analysis endpoint and return the data dict."""
    res = client.post(
        '/api/analyze-url',
        data=json.dumps({'url': url}),
        content_type='application/json'
    )
    assert res.status_code == 200, f"Expected 200, got {res.status_code}"
    body = res.get_json()
    assert body['success'] is True, f"Expected success=True, got: {body}"
    return body['data']


def post_message(client, message: str) -> Dict[str, Any]:
    """POST a message to the analysis endpoint and return the data dict."""
    res = client.post(
        '/api/analyze-message',
        data=json.dumps({'message': message, 'analyze_urls': True}),
        content_type='application/json'
    )
    assert res.status_code == 200, f"Expected 200, got {res.status_code}"
    body = res.get_json()
    assert body['success'] is True, f"Expected success=True, got: {body}"
    return body['data']


# ══════════════════════════════════════════════════════════════════════════════
# GROUP A — INTEGRATION: URL EXPLANATION
# ══════════════════════════════════════════════════════════════════════════════

class TestUrlExplanationIntegration:

    def test_url_response_contains_explanation_key(self):
        """Integration: URL analysis response must include an 'explanation' key."""
        client = get_client()
        data = post_url(client, 'https://www.google.com')
        assert 'explanation' in data, "'explanation' key missing from URL analysis response."

    def test_url_explanation_has_required_keys(self):
        """Integration: Explanation dict must have all required sub-keys."""
        client = get_client()
        data = post_url(client, 'https://www.google.com')
        exp = data['explanation']
        required = ['summary', 'ml_evidence', 'rule_evidence', 'feature_evidence',
                    'risk_contribution', 'what_does_this_mean', 'recommendation',
                    'investigation_stages', 'scan_type']
        for key in required:
            assert key in exp, f"Missing required explanation key: '{key}'"

    def test_url_explanation_scan_type_is_url(self):
        """Integration: scan_type must be 'url' for URL analysis."""
        client = get_client()
        data = post_url(client, 'http://192.168.1.100/login.php')
        assert data['explanation']['scan_type'] == 'url'

    def test_url_ml_evidence_contains_numeric_probability(self):
        """Integration: ml_evidence must contain an actual numeric phishing probability."""
        client = get_client()
        data = post_url(client, 'http://secure-paypal.tk/verify')
        ml_ev = data['explanation']['ml_evidence']
        assert 'phishing_probability' in ml_ev, "ml_evidence missing phishing_probability."
        prob = ml_ev['phishing_probability']
        assert isinstance(prob, float), f"phishing_probability must be float, got {type(prob)}"
        assert 0.0 <= prob <= 1.0, f"phishing_probability must be in [0, 1], got {prob}"

    def test_url_ml_evidence_probability_matches_api_confidence(self):
        """Integration: explanation ML probability must match the top-level confidence field."""
        client = get_client()
        data = post_url(client, 'https://github.com')
        if data.get('model_loaded'):
            confidence = data.get('confidence') or data.get('ml_probability_estimate')
            exp_prob = data['explanation']['ml_evidence']['phishing_probability']
            assert abs(confidence - exp_prob) < 0.0001, \
                f"ML probability mismatch: confidence={confidence}, explanation={exp_prob}"

    def test_url_rule_evidence_matches_triggered_rules(self):
        """Integration: rule_evidence count must match triggered_rules count."""
        client = get_client()
        data = post_url(client, 'http://192.168.1.1/admin@paypal.com/login')
        triggered = data.get('triggered_rules', [])
        rule_ev = data['explanation']['rule_evidence']
        assert len(rule_ev) == len(triggered), \
            f"rule_evidence count ({len(rule_ev)}) != triggered_rules count ({len(triggered)})"

    def test_url_risk_contribution_ml_points_matches_breakdown(self):
        """Integration: explanation risk_contribution.ml_points must match calculation_breakdown."""
        client = get_client()
        data = post_url(client, 'http://bit.ly/test')
        bd = data.get('calculation_breakdown', {})
        rc = data['explanation']['risk_contribution']
        if 'ml_base_points' in bd:
            assert rc['ml_points'] == bd['ml_base_points'], \
                f"ml_points mismatch: explanation={rc['ml_points']}, breakdown={bd['ml_base_points']}"

    def test_url_risk_contribution_total_matches_risk_score(self):
        """Integration: total_score in risk_contribution must equal top-level risk_score."""
        client = get_client()
        data = post_url(client, 'http://192.168.5.5/phish@attacker.tk')
        assert data['explanation']['risk_contribution']['total_score'] == data['risk_score'], \
            "risk_contribution total_score does not match top-level risk_score."

    def test_url_risk_score_bounded_0_100(self):
        """Integration: risk score must always be in [0, 100]."""
        client = get_client()
        for url in ['https://google.com', 'http://192.168.1.1/login@evil.tk/verify']:
            data = post_url(client, url)
            score = data['risk_score']
            assert 0 <= score <= 100, f"Risk score {score} out of bounds for URL: {url}"

    def test_url_feature_evidence_length_is_25(self):
        """Integration: feature_evidence must contain exactly 25 items (one per feature)."""
        client = get_client()
        data = post_url(client, 'https://www.example.com')
        assert len(data['explanation']['feature_evidence']) == 25, \
            f"Expected 25 feature_evidence items, got {len(data['explanation']['feature_evidence'])}"

    def test_url_https_not_described_as_safe(self):
        """Integration: HTTPS feature description must not claim the site is 'safe' or 'legitimate'."""
        client = get_client()
        data = post_url(client, 'https://www.google.com')
        feature_evidence = data['explanation']['feature_evidence']
        https_entries = [f for f in feature_evidence if f['name'] == 'uses_https']
        assert https_entries, "No feature_evidence entry for 'uses_https'."
        sentence = https_entries[0]['sentence'].lower()
        assert 'safe' not in sentence, "HTTPS feature description must not use the word 'safe'."
        assert 'not' in sentence or 'does not' in sentence or 'does not establish' in sentence, \
            f"HTTPS description must include a disclaimer about legitimacy. Got: '{sentence}'"

    def test_url_legitimate_url_low_risk(self):
        """Integration: A well-known legitimate URL must produce Low or Medium risk and a coherent explanation."""
        client = get_client()
        data = post_url(client, 'https://www.google.com')
        assert data['risk_level'] in ('Low', 'Medium'), \
            f"Expected Low/Medium for google.com, got {data['risk_level']}"
        assert data['explanation']['summary'], "Explanation summary must not be empty."

    def test_url_suspicious_url_produces_explanation(self):
        """Integration: A suspicious URL must produce populated rule_evidence and elevated risk."""
        client = get_client()
        data = post_url(client, 'http://192.168.1.1/login?user=admin@evil.tk')
        assert data['risk_score'] > 20, "Expected elevated risk score for raw IP URL."
        assert len(data['explanation']['rule_evidence']) > 0, \
            "Expected at least one rule_evidence entry for a suspicious URL."

    def test_url_explanation_investigation_stages_present(self):
        """Integration: investigation_stages must be a non-empty list."""
        client = get_client()
        data = post_url(client, 'https://www.example.com')
        stages = data['explanation']['investigation_stages']
        assert isinstance(stages, list), "investigation_stages must be a list."
        assert len(stages) >= 4, f"Expected at least 4 investigation stages, got {len(stages)}"

    def test_url_no_fabricated_indicator_in_rule_evidence(self):
        """Integration: rule_evidence items must match triggered_rules — no invented content."""
        client = get_client()
        data = post_url(client, 'https://www.google.com')
        triggered_names = {r['name'] for r in data.get('triggered_rules', [])}
        for ev in data['explanation']['rule_evidence']:
            assert ev['rule'] in triggered_names, \
                f"Explanation contains fabricated rule not in triggered_rules: '{ev['rule']}'"

    def test_url_existing_api_fields_preserved(self):
        """Integration: All existing API fields must remain present after Phase 9 changes."""
        client = get_client()
        data = post_url(client, 'https://www.google.com')
        preserved_fields = [
            'prediction', 'risk_score', 'risk_level', 'reasons',
            'recommendation', 'triggered_rules', 'calculation_breakdown', 'features'
        ]
        for field in preserved_fields:
            assert field in data, f"Existing API field '{field}' is missing after Phase 9."

    def test_url_global_feature_importance_labeling(self):
        """Integration: If global_feature_importance exists, it must not be labeled as per-sample."""
        client = get_client()
        data = post_url(client, 'https://www.google.com')
        exp = data.get('explanation', {})
        if 'global_feature_importance' in exp:
            gfi = exp['global_feature_importance']
            label = gfi.get('label', '').lower()
            note = gfi.get('note', '').lower()
            assert 'global' in label or 'model' in label, \
                f"global_feature_importance label must be 'global' or 'model', got '{label}'"
            assert 'not a per-sample' in note or 'not' in note, \
                "global_feature_importance note must clarify it is NOT per-sample."


# ══════════════════════════════════════════════════════════════════════════════
# GROUP B — INTEGRATION: MESSAGE EXPLANATION
# ══════════════════════════════════════════════════════════════════════════════

class TestMessageExplanationIntegration:

    def test_message_response_contains_explanation(self):
        """Integration: Message analysis response must include an 'explanation' key."""
        client = get_client()
        data = post_message(client, 'Hello, how are you?')
        assert 'explanation' in data, "'explanation' key missing from message analysis response."

    def test_message_explanation_scan_type_is_message(self):
        """Integration: scan_type must be 'message' for message analysis."""
        client = get_client()
        data = post_message(client, 'Hello friend!')
        assert data['explanation']['scan_type'] == 'message'

    def test_message_without_url_has_no_url_evidence(self):
        """Integration: A message with no embedded URL must have empty url_evidence list."""
        client = get_client()
        data = post_message(client, 'Hi, please call me back tomorrow.')
        url_evidence = data['explanation'].get('url_evidence', [])
        url_evidence_summary = data['explanation'].get('url_evidence_summary', {})
        assert isinstance(url_evidence, list), "url_evidence must be a list."
        assert len(url_evidence) == 0, \
            f"Message without URL must have empty url_evidence, got {len(url_evidence)} items."
        assert url_evidence_summary.get('url_count', 0) == 0, \
            "url_evidence_summary.url_count must be 0 for message without URLs."

    def test_message_with_url_has_url_evidence(self):
        """Integration: A message with an embedded URL must include url_evidence."""
        client = get_client()
        data = post_message(
            client,
            'URGENT: Your account has been suspended! Verify at http://bank-verify.tk/login now.'
        )
        url_evidence = data['explanation'].get('url_evidence', [])
        if data.get('url_analyses'):  # Only verify if URL cascade was actually executed
            assert len(url_evidence) > 0, \
                "Expected url_evidence when message contains a URL that was analyzed."

    def test_message_risk_contribution_totals_consistent(self):
        """Integration: risk_contribution total_score must equal top-level risk_score."""
        client = get_client()
        data = post_message(
            client,
            'URGENT: Verify your account immediately at http://paypal-verify.xyz'
        )
        rc = data['explanation']['risk_contribution']
        assert rc['total_score'] == data['risk_score'], \
            f"risk_contribution total_score ({rc['total_score']}) != risk_score ({data['risk_score']})"

    def test_message_risk_score_bounded(self):
        """Integration: Message risk score must be in [0, 100]."""
        client = get_client()
        for msg in ['Hi there!', 'URGENT verify account OTP http://phish.tk click here now!']:
            data = post_message(client, msg)
            assert 0 <= data['risk_score'] <= 100, \
                f"Message risk score {data['risk_score']} out of [0, 100] bounds."

    def test_message_ml_evidence_uses_correct_terminology(self):
        """Integration: ml_evidence role must not call the text model a 'phishing classifier'."""
        client = get_client()
        data = post_message(client, 'Hello world')
        role = data['explanation']['ml_evidence'].get('role', '').lower()
        # Should mention spam/malicious — must NOT be labeled purely as phishing
        assert 'phishing' not in role or 'malicious' in role or 'spam' in role, \
            f"Message model role must use 'malicious/spam' terminology, got: '{role}'"

    def test_message_indicator_evidence_matches_detected_indicators(self):
        """Integration: indicator_evidence count must match detected_indicators count."""
        client = get_client()
        data = post_message(client, 'URGENT: OTP 123456 verify account immediately!')
        detected = data.get('detected_indicators', [])
        ind_ev = data['explanation'].get('indicator_evidence', [])
        assert len(ind_ev) == len(detected), \
            f"indicator_evidence ({len(ind_ev)}) != detected_indicators ({len(detected)})"

    def test_message_investigation_stages_no_url_analysis_for_no_url_message(self):
        """Integration: Timeline must not include a URL analysis stage when no URL present."""
        client = get_client()
        data = post_message(client, 'Please call me tomorrow for the meeting.')
        stages = data['explanation'].get('investigation_stages', [])
        stage_names = [s['stage'].lower() for s in stages]
        # URL analysis stage must not appear when there are no embedded URLs
        url_stages = [n for n in stage_names if 'url extraction' in n or 'cascade' in n]
        extracted_urls = data.get('extracted_urls', [])
        if not extracted_urls:
            assert len(url_stages) == 0, \
                f"Timeline must not show URL Analysis stage when no URLs found. Stages: {stage_names}"

    def test_message_existing_api_fields_preserved(self):
        """Integration: All existing message API fields must remain present after Phase 9."""
        client = get_client()
        data = post_message(client, 'Test message for field preservation check.')
        preserved = [
            'prediction', 'risk_score', 'risk_level', 'recommendation',
            'detected_indicators', 'extracted_urls', 'url_analyses',
            'calculation_breakdown', 'model_loaded'
        ]
        for field in preserved:
            assert field in data, f"Existing API field '{field}' missing after Phase 9."


# ══════════════════════════════════════════════════════════════════════════════
# GROUP C — UNIT: FEATURE DESCRIPTIONS
# ══════════════════════════════════════════════════════════════════════════════

class TestFeatureDescriptions:

    def test_all_25_features_have_descriptions(self):
        """Unit: Every one of the 25 feature names must map to a non-empty description."""
        from ml.feature_descriptions import describe_feature, FEATURE_DESCRIPTIONS
        from ml.feature_extractor import FEATURE_NAMES
        for name in FEATURE_NAMES:
            assert name in FEATURE_DESCRIPTIONS, f"Feature '{name}' has no description entry."
            sentence, level = describe_feature(name, 0)
            assert sentence, f"Feature '{name}' produced an empty sentence."
            assert level in ('normal', 'noteworthy', 'suspicious'), \
                f"Feature '{name}' produced invalid level '{level}'."

    def test_has_ip_address_is_suspicious_when_set(self):
        """Unit: has_ip_address=1 must produce 'suspicious' observation level."""
        from ml.feature_descriptions import describe_feature
        _, level = describe_feature('has_ip_address', 1)
        assert level == 'suspicious', f"has_ip_address=1 must be 'suspicious', got '{level}'"

    def test_has_ip_address_is_normal_when_zero(self):
        """Unit: has_ip_address=0 must produce 'normal' observation level."""
        from ml.feature_descriptions import describe_feature
        _, level = describe_feature('has_ip_address', 0)
        assert level == 'normal', f"has_ip_address=0 must be 'normal', got '{level}'"

    def test_uses_https_description_does_not_say_safe(self):
        """Unit: uses_https=1 description must not use the word 'safe' or imply legitimacy."""
        from ml.feature_descriptions import describe_feature
        sentence, _ = describe_feature('uses_https', 1)
        assert 'safe' not in sentence.lower(), \
            f"uses_https=1 description must not use 'safe'. Got: '{sentence}'"

    def test_uses_https_description_contains_disclaimer(self):
        """Unit: uses_https=1 description must note that HTTPS does not prove legitimacy."""
        from ml.feature_descriptions import describe_feature
        sentence, _ = describe_feature('uses_https', 1)
        lower = sentence.lower()
        has_disclaimer = 'does not' in lower or 'not' in lower
        assert has_disclaimer, \
            f"uses_https description must include a disclaimer. Got: '{sentence}'"

    def test_has_suspicious_tld_is_suspicious(self):
        """Unit: has_suspicious_tld=1 must produce 'suspicious' observation level."""
        from ml.feature_descriptions import describe_feature
        _, level = describe_feature('has_suspicious_tld', 1)
        assert level == 'suspicious', f"has_suspicious_tld=1 must be 'suspicious', got '{level}'"

    def test_is_url_shortener_is_suspicious(self):
        """Unit: is_url_shortener=1 must produce 'suspicious' observation level."""
        from ml.feature_descriptions import describe_feature
        _, level = describe_feature('is_url_shortener', 1)
        assert level == 'suspicious', f"is_url_shortener=1 must be 'suspicious', got '{level}'"

    def test_has_at_symbol_is_suspicious(self):
        """Unit: has_at_symbol=1 must produce 'suspicious' observation level."""
        from ml.feature_descriptions import describe_feature
        _, level = describe_feature('has_at_symbol', 1)
        assert level == 'suspicious', f"has_at_symbol=1 must be 'suspicious', got '{level}'"

    def test_describe_all_features_returns_25_items(self):
        """Unit: describe_all_features must return exactly 25 items for a standard feature dict."""
        from ml.feature_descriptions import describe_all_features
        from ml.feature_extractor import extract_url_features
        features = extract_url_features('https://www.google.com')
        result = describe_all_features(features)
        assert len(result) == 25, f"Expected 25 feature descriptions, got {len(result)}"

    def test_unknown_feature_returns_graceful_fallback(self):
        """Unit: An unknown feature name must return a non-empty fallback sentence."""
        from ml.feature_descriptions import describe_feature
        sentence, level = describe_feature('nonexistent_feature_xyz', 42)
        assert sentence, "Unknown feature must return a non-empty fallback sentence."
        assert level == 'normal', "Unknown feature must default to 'normal' observation level."


# ══════════════════════════════════════════════════════════════════════════════
# GROUP D — UNIT: EXPLANATION BUILDER
# ══════════════════════════════════════════════════════════════════════════════

class TestExplanationBuilder:

    def _get_mock_url_inputs(self):
        """Build realistic mock inputs by calling the actual extractors."""
        from ml.feature_extractor import extract_url_features
        from services.rule_engine import evaluate_rules
        from services.risk_engine import calculate_url_risk
        url = 'http://192.168.1.1/login'
        features = extract_url_features(url)
        rules = evaluate_rules(features)
        risk_data = calculate_url_risk(0.82, rules, features)
        return url, features, rules, risk_data

    def test_build_url_explanation_returns_dict_with_required_keys(self):
        """Unit: build_url_explanation must return a dict with all required keys."""
        from services.explanation_builder import build_url_explanation
        url, features, rules, risk_data = self._get_mock_url_inputs()
        exp = build_url_explanation(url, features, 0.82, 'Phishing', risk_data, rules)
        required = ['summary', 'ml_evidence', 'rule_evidence', 'feature_evidence',
                    'risk_contribution', 'what_does_this_mean', 'recommendation',
                    'investigation_stages', 'scan_type']
        for key in required:
            assert key in exp, f"build_url_explanation missing key: '{key}'"

    def test_build_url_explanation_risk_contribution_totals_correct(self):
        """Unit: risk_contribution.total_score must equal risk_data risk_score."""
        from services.explanation_builder import build_url_explanation
        url, features, rules, risk_data = self._get_mock_url_inputs()
        exp = build_url_explanation(url, features, 0.82, 'Phishing', risk_data, rules)
        assert exp['risk_contribution']['total_score'] == risk_data['risk_score']

    def test_build_url_explanation_rule_evidence_count_matches(self):
        """Unit: rule_evidence length must equal number of triggered rules passed in."""
        from services.explanation_builder import build_url_explanation
        url, features, rules, risk_data = self._get_mock_url_inputs()
        exp = build_url_explanation(url, features, 0.82, 'Phishing', risk_data, rules)
        assert len(exp['rule_evidence']) == len(rules)

    def test_build_url_explanation_no_global_importance_without_model(self):
        """Unit: global_feature_importance must be absent when model=None."""
        from services.explanation_builder import build_url_explanation
        url, features, rules, risk_data = self._get_mock_url_inputs()
        exp = build_url_explanation(url, features, 0.82, 'Phishing', risk_data, rules, model=None)
        assert 'global_feature_importance' not in exp, \
            "global_feature_importance must be absent when model=None."

    def test_build_message_explanation_returns_dict_with_required_keys(self):
        """Unit: build_message_explanation must return a dict with all required keys."""
        from services.explanation_builder import build_message_explanation
        from services.risk_engine import calculate_message_risk
        risk_data = calculate_message_risk(0.65, [], max_url_risk=0)
        exp = build_message_explanation(
            message_preview='Test message',
            ml_probability=0.65,
            ml_prediction='Malicious/Spam',
            risk_data=risk_data,
            detected_indicators=[],
            url_analyses=[],
            text_evidence=[],
        )
        required = ['summary', 'ml_evidence', 'indicator_evidence', 'url_evidence',
                    'risk_contribution', 'what_does_this_mean', 'recommendation',
                    'investigation_stages', 'scan_type']
        for key in required:
            assert key in exp, f"build_message_explanation missing key: '{key}'"

    def test_build_message_explanation_no_url_cascade_stage_for_no_urls(self):
        """Unit: investigation_stages must not include a URL cascade stage when url_analyses is empty."""
        from services.explanation_builder import build_message_explanation
        from services.risk_engine import calculate_message_risk
        risk_data = calculate_message_risk(0.3, [], max_url_risk=0)
        exp = build_message_explanation(
            message_preview='Hello!',
            ml_probability=0.3,
            ml_prediction='Legitimate/Ham',
            risk_data=risk_data,
            detected_indicators=[],
            url_analyses=[],
            text_evidence=[],
        )
        stage_names = [s['stage'].lower() for s in exp['investigation_stages']]
        url_stages = [n for n in stage_names if 'url extraction' in n or 'cascade' in n]
        assert len(url_stages) == 0, \
            f"URL cascade stage must not appear when no URLs analyzed. Stages: {stage_names}"

    def test_build_message_explanation_url_cascade_stage_present_with_urls(self):
        """Unit: investigation_stages must include a URL cascade stage when url_analyses is non-empty."""
        from services.explanation_builder import build_message_explanation
        from services.risk_engine import calculate_message_risk
        mock_url_result = {
            'success': True,
            'normalized_url': 'http://evil.tk',
            'prediction': 'Phishing',
            'risk_score': 80,
            'risk_level': 'Critical',
            'triggered_rules': [],
            'explanation': {},
        }
        risk_data = calculate_message_risk(0.9, [], max_url_risk=80)
        exp = build_message_explanation(
            message_preview='Click here now!',
            ml_probability=0.9,
            ml_prediction='Malicious/Spam',
            risk_data=risk_data,
            detected_indicators=[],
            url_analyses=[mock_url_result],
            text_evidence=[],
        )
        stage_names = [s['stage'].lower() for s in exp['investigation_stages']]
        url_stages = [n for n in stage_names if 'url extraction' in n or 'cascade' in n]
        assert len(url_stages) > 0, "URL cascade stage must appear when url_analyses is non-empty."


# ══════════════════════════════════════════════════════════════════════════════
# Top-Level Test Wrappers for run_tests.py discovery
# ══════════════════════════════════════════════════════════════════════════════

# Group A: URL Explanation Integration Tests
def test_p9_url_response_contains_explanation():
    TestUrlExplanationIntegration().test_url_response_contains_explanation_key()

def test_p9_url_explanation_has_required_keys():
    TestUrlExplanationIntegration().test_url_explanation_has_required_keys()

def test_p9_url_explanation_scan_type_is_url():
    TestUrlExplanationIntegration().test_url_explanation_scan_type_is_url()

def test_p9_url_ml_evidence_contains_numeric_probability():
    TestUrlExplanationIntegration().test_url_ml_evidence_contains_numeric_probability()

def test_p9_url_ml_evidence_probability_matches_api_confidence():
    TestUrlExplanationIntegration().test_url_ml_evidence_probability_matches_api_confidence()

def test_p9_url_rule_evidence_matches_triggered_rules():
    TestUrlExplanationIntegration().test_url_rule_evidence_matches_triggered_rules()

def test_p9_url_risk_contribution_ml_points_matches_breakdown():
    TestUrlExplanationIntegration().test_url_risk_contribution_ml_points_matches_breakdown()

def test_p9_url_risk_contribution_total_matches_risk_score():
    TestUrlExplanationIntegration().test_url_risk_contribution_total_matches_risk_score()

def test_p9_url_risk_score_bounded_0_100():
    TestUrlExplanationIntegration().test_url_risk_score_bounded_0_100()

def test_p9_url_feature_evidence_length_is_25():
    TestUrlExplanationIntegration().test_url_feature_evidence_length_is_25()

def test_p9_url_https_not_described_as_safe():
    TestUrlExplanationIntegration().test_url_https_not_described_as_safe()

def test_p9_url_legitimate_url_low_risk():
    TestUrlExplanationIntegration().test_url_legitimate_url_low_risk()

def test_p9_url_suspicious_url_produces_explanation():
    TestUrlExplanationIntegration().test_url_suspicious_url_produces_explanation()

def test_p9_url_explanation_investigation_stages_present():
    TestUrlExplanationIntegration().test_url_explanation_investigation_stages_present()

def test_p9_url_no_fabricated_indicator_in_rule_evidence():
    TestUrlExplanationIntegration().test_url_no_fabricated_indicator_in_rule_evidence()

def test_p9_url_existing_api_fields_preserved():
    TestUrlExplanationIntegration().test_url_existing_api_fields_preserved()

def test_p9_url_global_feature_importance_labeling():
    TestUrlExplanationIntegration().test_url_global_feature_importance_labeling()

# Group B: Message Explanation Integration Tests
def test_p9_message_response_contains_explanation():
    TestMessageExplanationIntegration().test_message_response_contains_explanation()

def test_p9_message_explanation_scan_type_is_message():
    TestMessageExplanationIntegration().test_message_explanation_scan_type_is_message()

def test_p9_message_without_url_has_no_url_evidence():
    TestMessageExplanationIntegration().test_message_without_url_has_no_url_evidence()

def test_p9_message_with_url_has_url_evidence():
    TestMessageExplanationIntegration().test_message_with_url_has_url_evidence()

def test_p9_message_risk_contribution_totals_consistent():
    TestMessageExplanationIntegration().test_message_risk_contribution_totals_consistent()

def test_p9_message_risk_score_bounded():
    TestMessageExplanationIntegration().test_message_risk_score_bounded()

def test_p9_message_ml_evidence_uses_correct_terminology():
    TestMessageExplanationIntegration().test_message_ml_evidence_uses_correct_terminology()

def test_p9_message_indicator_evidence_matches_detected_indicators():
    TestMessageExplanationIntegration().test_message_indicator_evidence_matches_detected_indicators()

def test_p9_message_investigation_stages_no_url_analysis_for_no_url_message():
    TestMessageExplanationIntegration().test_message_investigation_stages_no_url_analysis_for_no_url_message()

def test_p9_message_existing_api_fields_preserved():
    TestMessageExplanationIntegration().test_message_existing_api_fields_preserved()

# Group C: Feature Description Unit Tests
def test_p9_all_25_features_have_descriptions():
    TestFeatureDescriptions().test_all_25_features_have_descriptions()

def test_p9_has_ip_address_is_suspicious_when_set():
    TestFeatureDescriptions().test_has_ip_address_is_suspicious_when_set()

def test_p9_has_ip_address_is_normal_when_zero():
    TestFeatureDescriptions().test_has_ip_address_is_normal_when_zero()

def test_p9_uses_https_description_does_not_say_safe():
    TestFeatureDescriptions().test_uses_https_description_does_not_say_safe()

def test_p9_uses_https_description_contains_disclaimer():
    TestFeatureDescriptions().test_uses_https_description_contains_disclaimer()

def test_p9_has_suspicious_tld_is_suspicious():
    TestFeatureDescriptions().test_has_suspicious_tld_is_suspicious()

def test_p9_is_url_shortener_is_suspicious():
    TestFeatureDescriptions().test_is_url_shortener_is_suspicious()

def test_p9_has_at_symbol_is_suspicious():
    TestFeatureDescriptions().test_has_at_symbol_is_suspicious()

def test_p9_describe_all_features_returns_25_items():
    TestFeatureDescriptions().test_describe_all_features_returns_25_items()

def test_p9_unknown_feature_returns_graceful_fallback():
    TestFeatureDescriptions().test_unknown_feature_returns_graceful_fallback()

# Group D: Explanation Builder Unit Tests
def test_p9_build_url_explanation_returns_dict_with_required_keys():
    TestExplanationBuilder().test_build_url_explanation_returns_dict_with_required_keys()

def test_p9_build_url_explanation_risk_contribution_totals_correct():
    TestExplanationBuilder().test_build_url_explanation_risk_contribution_totals_correct()

def test_p9_build_url_explanation_rule_evidence_count_matches():
    TestExplanationBuilder().test_build_url_explanation_rule_evidence_count_matches()

def test_p9_build_url_explanation_no_global_importance_without_model():
    TestExplanationBuilder().test_build_url_explanation_no_global_importance_without_model()

def test_p9_build_message_explanation_returns_dict_with_required_keys():
    TestExplanationBuilder().test_build_message_explanation_returns_dict_with_required_keys()

def test_p9_build_message_explanation_no_url_cascade_stage_for_no_urls():
    TestExplanationBuilder().test_build_message_explanation_no_url_cascade_stage_for_no_urls()

def test_p9_build_message_explanation_url_cascade_stage_present_with_urls():
    TestExplanationBuilder().test_build_message_explanation_url_cascade_stage_present_with_urls()

