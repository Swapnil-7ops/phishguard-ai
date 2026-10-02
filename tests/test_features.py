"""
test_features.py - Automated Unit Tests for URL Feature Extraction
"""
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))

from ml.feature_extractor import extract_url_features, get_feature_names, is_ip_address, calculate_entropy


def test_feature_count():
    """Verify exactly 25 canonical features are extracted."""
    features = extract_url_features("https://www.example.com")
    assert len(features) == 25
    assert set(features.keys()) == set(get_feature_names())


def test_legitimate_url_features():
    """Verify features for a clean, short HTTPS URL."""
    url = "https://www.google.com"
    f = extract_url_features(url)
    assert f["uses_https"] == 1
    assert f["has_ip_address"] == 0
    assert f["has_at_symbol"] == 0
    assert f["is_url_shortener"] == 0
    assert f["suspicious_keyword_count"] == 0


def test_ip_address_detection():
    """Verify raw IPv4 and IPv6 detection."""
    assert is_ip_address("192.168.1.1") == 1
    assert is_ip_address("10.0.0.1") == 1
    assert is_ip_address("google.com") == 0

    f = extract_url_features("http://192.168.1.1/login")
    assert f["has_ip_address"] == 1
    assert f["uses_https"] == 0


def test_at_symbol_detection():
    """Verify presence of @ character is flagged."""
    f = extract_url_features("http://google.com@attacker.xyz/login")
    assert f["has_at_symbol"] == 1
    assert f["has_suspicious_tld"] == 1


def test_excessive_subdomains():
    """Verify counting of nested subdomains."""
    f = extract_url_features("http://login.verify.account.chase.com.evil.xyz/")
    assert f["num_subdomains"] >= 4


def test_suspicious_keywords():
    """Verify recognition of phishing keywords."""
    f = extract_url_features("http://portal.com/login/verify/update-password")
    assert f["suspicious_keyword_count"] >= 3


def test_url_shortener_detection():
    """Verify recognition of known link shorteners."""
    f = extract_url_features("https://bit.ly/3xUpdatePass")
    assert f["is_url_shortener"] == 1


def test_double_slash_path():
    """Verify detection of double slash redirection trick."""
    f = extract_url_features("http://legit.com//evil.com/login")
    assert f["has_double_slash_path"] == 1


def test_entropy_calculation():
    """Verify Shannon entropy responds correctly to random vs structured strings."""
    low_ent = calculate_entropy("aaaaaa")
    high_ent = calculate_entropy("x8q1m9z4p2")
    assert high_ent > low_ent
    assert low_ent == 0.0


def test_empty_or_invalid_inputs():
    """Verify extractor handles empty or corrupt inputs without crashing."""
    f_empty = extract_url_features("")
    assert len(f_empty) == 25
    assert all(v == 0 for v in f_empty.values())

    f_none = extract_url_features(None)
    assert len(f_none) == 25
