"""
test_rules.py - Automated Unit Tests for the Security Rule Engine
"""
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))

from services.rule_engine import evaluate_rules, RULES


def test_registered_rules_integrity():
    """Verify each rule has expected attributes and valid severity."""
    valid_severities = {"high", "medium", "low", "critical"}
    assert len(RULES) >= 10
    for r in RULES:
        assert "rule_id" in r
        assert "name" in r
        assert "severity" in r
        assert r["severity"] in valid_severities
        assert "score_impact" in r
        assert r["score_impact"] > 0
        assert callable(r["detect"])


def test_ip_rule_trigger():
    """Verify IP address rule triggers when has_ip_address is 1."""
    features = {"has_ip_address": 1}
    triggered = evaluate_rules(features)
    ids = [r["rule_id"] for r in triggered]
    assert "URL_IP" in ids


def test_at_symbol_rule_trigger():
    """Verify @ symbol rule triggers."""
    features = {"has_at_symbol": 1}
    triggered = evaluate_rules(features)
    ids = [r["rule_id"] for r in triggered]
    assert "URL_AT" in ids


def test_shortener_rule_trigger():
    """Verify URL shortener rule triggers."""
    features = {"is_url_shortener": 1}
    triggered = evaluate_rules(features)
    ids = [r["rule_id"] for r in triggered]
    assert "URL_SHORTENER" in ids


def test_clean_features_no_unwarranted_triggers():
    """Verify benign features trigger zero high severity rules."""
    features = {
        "has_ip_address": 0,
        "has_at_symbol": 0,
        "is_url_shortener": 0,
        "has_suspicious_tld": 0,
        "num_subdomains": 0,
        "suspicious_keyword_count": 0,
        "uses_https": 1,
        "url_length": 25,
        "num_hyphens": 0,
        "digit_count": 0,
        "encoded_char_count": 0,
        "has_double_slash_path": 0,
        "hostname_entropy": 2.1
    }
    triggered = evaluate_rules(features)
    assert len(triggered) == 0
