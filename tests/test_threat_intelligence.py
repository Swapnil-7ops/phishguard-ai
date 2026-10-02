"""
test_threat_intelligence.py — Phase 11 Threat Intelligence Automated Test Suite

Tests all Threat Intelligence functionality with 100% mocked external calls.
Zero outbound HTTP requests to real external providers or user URLs.

Compatible with both pytest and the unified runner (run_tests.py).
"""
import os
import sys
import time
from unittest.mock import patch, MagicMock

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from services.threat_intelligence.base import ThreatIntelResult, ThreatIntelProvider
from services.threat_intelligence.virustotal import VirusTotalProvider
from services.threat_intelligence.cache import SimpleThreatIntelCache
from services.threat_intelligence.service import (
    ThreatIntelService,
    get_threat_intel_service,
    reset_threat_intel_service,
)
from services.risk_engine import calculate_url_risk
from services.explanation_builder import build_url_explanation


# ─────────────────────────────────────────────────────────────────────────────
# Helper factories
# ─────────────────────────────────────────────────────────────────────────────

def _mock_vt_response(status_code: int, json_data: dict = None):
    mock = MagicMock()
    mock.status_code = status_code
    mock.json.return_value = json_data if json_data is not None else {}
    return mock


# ─────────────────────────────────────────────────────────────────────────────
# 1. VIRUSTOTAL PROVIDER UNIT TESTS
# ─────────────────────────────────────────────────────────────────────────────

def test_vt_provider_not_configured():
    """Provider without API key returns not_configured with 0 detections."""
    p = VirusTotalProvider(api_key="")
    assert not p.is_configured()
    res = p.lookup_url("https://example.com")
    assert isinstance(res, ThreatIntelResult)
    assert res.status == "not_configured"
    assert res.detections == 0
    assert not res.queried


def test_vt_provider_success_malicious():
    """Provider with >= 5 malicious detections returns success with correct counts."""
    p = VirusTotalProvider(api_key="TEST_API_KEY")
    mock_resp = _mock_vt_response(200, {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 8, "suspicious": 1, "harmless": 50, "undetected": 10
                },
                "reputation": -35,
                "categories": {"vendor1": "phishing"}
            }
        }
    })
    with patch("requests.get", return_value=mock_resp):
        res = p.lookup_url("https://phishing-site.tk")
    assert res.status == "success"
    assert res.detections == 8
    assert res.malicious is True
    assert res.total_engines == 69
    assert res.reputation == -35
    assert res.categories == ["phishing"]


def test_vt_provider_success_suspicious_only():
    """Provider with 0 malicious but > 0 suspicious returns suspicious status."""
    p = VirusTotalProvider(api_key="TEST_API_KEY")
    mock_resp = _mock_vt_response(200, {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 0, "suspicious": 3, "harmless": 40, "undetected": 20
                },
                "reputation": -5
            }
        }
    })
    with patch("requests.get", return_value=mock_resp):
        res = p.lookup_url("https://suspicious-site.net")
    assert res.status == "success"
    assert res.detections == 0
    assert res.suspicious_detections == 3
    assert res.suspicious is True
    assert res.malicious is False


def test_vt_provider_success_clean():
    """Provider with 0 detections returns clean success."""
    p = VirusTotalProvider(api_key="TEST_API_KEY")
    mock_resp = _mock_vt_response(200, {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 0, "suspicious": 0, "harmless": 65, "undetected": 5
                },
                "reputation": 80
            }
        }
    })
    with patch("requests.get", return_value=mock_resp):
        res = p.lookup_url("https://google.com")
    assert res.status == "success"
    assert res.detections == 0
    assert res.malicious is False
    assert res.suspicious is False


def test_vt_provider_404_not_found():
    """HTTP 404 maps to not_found safely."""
    p = VirusTotalProvider(api_key="TEST_API_KEY")
    mock_resp = _mock_vt_response(404)
    with patch("requests.get", return_value=mock_resp):
        res = p.lookup_url("https://unindexed-domain-xyz.com")
    assert res.status == "not_found"
    assert res.detections == 0
    assert res.error_code == "NOT_FOUND"


def test_vt_provider_429_rate_limited():
    """HTTP 429 maps to rate_limited without raising."""
    p = VirusTotalProvider(api_key="TEST_API_KEY")
    mock_resp = _mock_vt_response(429)
    with patch("requests.get", return_value=mock_resp):
        res = p.lookup_url("https://example.com")
    assert res.status == "rate_limited"
    assert res.error_code == "RATE_LIMITED"


def test_vt_provider_401_invalid_key():
    """HTTP 401 maps to error with INVALID_API_KEY."""
    p = VirusTotalProvider(api_key="BAD_KEY")
    mock_resp = _mock_vt_response(401)
    with patch("requests.get", return_value=mock_resp):
        res = p.lookup_url("https://example.com")
    assert res.status == "error"
    assert res.error_code == "INVALID_API_KEY"


def test_vt_provider_500_server_error():
    """HTTP 500 maps to error with HTTP_500 code."""
    p = VirusTotalProvider(api_key="TEST_API_KEY")
    mock_resp = _mock_vt_response(500)
    with patch("requests.get", return_value=mock_resp):
        res = p.lookup_url("https://example.com")
    assert res.status == "error"
    assert res.error_code == "HTTP_500"


def test_vt_provider_timeout_exception():
    """Timeout exception maps to timeout status safely."""
    import requests as req_lib
    p = VirusTotalProvider(api_key="TEST_API_KEY")
    with patch("requests.get", side_effect=req_lib.Timeout("Timed out")):
        res = p.lookup_url("https://example.com")
    assert res.status == "timeout"
    assert res.error_code == "TIMEOUT"


def test_vt_provider_connection_error():
    """Connection error maps to connection_error status safely."""
    import requests as req_lib
    p = VirusTotalProvider(api_key="TEST_API_KEY")
    with patch("requests.get", side_effect=req_lib.ConnectionError("Connection refused")):
        res = p.lookup_url("https://example.com")
    assert res.status == "connection_error"
    assert res.error_code == "CONNECTION_ERROR"


def test_vt_provider_malformed_json():
    """Non-JSON response handled safely without uncaught exception."""
    p = VirusTotalProvider(api_key="TEST_API_KEY")
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.side_effect = ValueError("Invalid JSON")
    with patch("requests.get", return_value=mock_resp):
        res = p.lookup_url("https://example.com")
    assert res.status == "error"
    assert res.error_code == "MALFORMED_RESPONSE"


def test_vt_provider_api_key_not_in_result():
    """API key must never appear in ThreatIntelResult or serialized dict."""
    p = VirusTotalProvider(api_key="SECRET_VIRUSTOTAL_KEY_999")
    mock_resp = _mock_vt_response(200, {
        "data": {"attributes": {"last_analysis_stats": {"malicious": 0}}}
    })
    with patch("requests.get", return_value=mock_resp):
        res = p.lookup_url("https://example.com")
    result_dict = res.to_dict()
    assert "SECRET_VIRUSTOTAL_KEY_999" not in str(result_dict)
    assert "SECRET_VIRUSTOTAL_KEY_999" not in str(res)


def test_vt_provider_url_never_fetched():
    """Target URL must NEVER be fetched — requests.get must only call VirusTotal."""
    p = VirusTotalProvider(api_key="TEST_API_KEY")
    mock_resp = _mock_vt_response(200, {
        "data": {"attributes": {"last_analysis_stats": {"malicious": 0}}}
    })
    with patch("requests.get", return_value=mock_resp) as mock_get:
        p.lookup_url("https://dangerous-malware-domain.ru/payload.exe")
    called_url = mock_get.call_args[0][0] if mock_get.call_args else ""
    assert "dangerous-malware-domain.ru" not in called_url
    assert "virustotal.com/api/v3/urls" in called_url


# ─────────────────────────────────────────────────────────────────────────────
# 2. CACHE TESTS
# ─────────────────────────────────────────────────────────────────────────────

def test_cache_miss_returns_none():
    """Cache returns None on miss."""
    cache = SimpleThreatIntelCache(default_ttl_sec=300)
    assert cache.get("https://unseen-url.com") is None


def test_cache_set_and_hit():
    """Cached entry is retrieved successfully."""
    cache = SimpleThreatIntelCache(default_ttl_sec=300)
    res = ThreatIntelResult(provider="VirusTotal", status="success", detections=5)
    cache.set("https://example.com", res)
    hit = cache.get("https://example.com")
    assert hit is not None
    assert hit.detections == 5
    assert hit.status == "success"


def test_cache_hit_prevents_duplicate_network_call():
    """Service lookup uses cache and avoids redundant provider calls."""
    cache = SimpleThreatIntelCache(default_ttl_sec=300)
    cached_res = ThreatIntelResult(
        provider="VirusTotal", status="success", detections=7, queried=True
    )
    cache.set("https://cached-example.com", cached_res)

    mock_provider = MagicMock()
    svc = ThreatIntelService(providers=[mock_provider], cache=cache)
    with patch.object(mock_provider, "is_configured", return_value=True):
        out = svc.lookup_url("https://cached-example.com")
    # Network provider was never called due to cache hit
    mock_provider.lookup_url.assert_not_called()
    assert out["cached"] is True
    assert out["summary"]["detections"] == 7


def test_cache_expiry():
    """Expired entry is pruned and returns None."""
    cache = SimpleThreatIntelCache(default_ttl_sec=0)
    res = ThreatIntelResult(provider="VirusTotal", status="success", detections=1)
    cache.set("https://expiring-soon.com", res, ttl_sec=0)
    time.sleep(0.02)
    assert cache.get("https://expiring-soon.com") is None


def test_cache_url_isolation():
    """Different URLs have distinct cache entries."""
    cache = SimpleThreatIntelCache(default_ttl_sec=300)
    res_a = ThreatIntelResult(provider="VirusTotal", status="success", detections=1)
    cache.set("https://domain-a.com", res_a)
    assert cache.get("https://domain-b.com") is None


# ─────────────────────────────────────────────────────────────────────────────
# 3. SERVICE ORCHESTRATION & RISK POINTS TESTS
# ─────────────────────────────────────────────────────────────────────────────

def test_service_singleton_lifecycle():
    """Singleton creation and reset works correctly."""
    reset_threat_intel_service()
    s1 = get_threat_intel_service()
    s2 = get_threat_intel_service()
    assert s1 is s2
    reset_threat_intel_service()
    s3 = get_threat_intel_service()
    assert s1 is not s3
    reset_threat_intel_service()


def test_service_unconfigured_returns_safe_defaults():
    """When no provider is configured, service returns not_configured and 0 points."""
    svc = ThreatIntelService(providers=[])
    assert not svc.is_enabled
    out = svc.lookup_url("https://example.com")
    assert out["enabled"] is False
    assert out["summary"]["status"] == "not_configured"
    assert out["summary"]["risk_points"] == 0
    assert out["summary"]["detections"] == 0


def test_calculate_ti_risk_points_zero_for_all_non_success_states():
    """Non-success states MUST yield exactly 0 risk points."""
    non_success_states = [
        "not_configured", "timeout", "connection_error",
        "rate_limited", "error", "not_found", "unknown"
    ]
    for st in non_success_states:
        for det in [0, 1, 5, 20]:
            pts = ThreatIntelService.calculate_ti_risk_points(st, det)
            assert pts == 0, f"Expected 0 for status '{st}' with {det} detections, got {pts}"


def test_calculate_ti_risk_points_zero_for_clean_success():
    """Successful provider response with 0 detections yields exactly 0 points."""
    assert ThreatIntelService.calculate_ti_risk_points("success", 0) == 0


def test_calculate_ti_risk_points_bounded_points():
    """Bounded points applied only for genuine detections: 1-4 -> 8 pts, >=5 -> 15 pts."""
    assert ThreatIntelService.calculate_ti_risk_points("success", 1) == 8
    assert ThreatIntelService.calculate_ti_risk_points("success", 4) == 8
    assert ThreatIntelService.calculate_ti_risk_points("success", 5) == 15
    assert ThreatIntelService.calculate_ti_risk_points("success", 45) == 15


# ─────────────────────────────────────────────────────────────────────────────
# 4. RISK ENGINE BOUNDED INTEGRATION TESTS
# ─────────────────────────────────────────────────────────────────────────────

def test_risk_engine_unconfigured_ti_preserves_local_score():
    """Unconfigured TI leaves local risk score untouched."""
    ti_unconfigured = {
        "summary": {"status": "not_configured", "detections": 0, "risk_points": 0}
    }
    res_none = calculate_url_risk(0.60, [], {}, threat_intel=None)
    res_unconf = calculate_url_risk(0.60, [], {}, threat_intel=ti_unconfigured)
    assert res_none["risk_score"] == res_unconf["risk_score"]
    assert res_unconf["calculation_breakdown"]["threat_intel_points"] == 0


def test_risk_engine_error_ti_preserves_local_score():
    """Error / timeout / rate_limited TI leaves local risk score untouched."""
    for st in ["timeout", "connection_error", "rate_limited", "error", "not_found"]:
        ti_err = {"summary": {"status": st, "detections": 0, "risk_points": 0}}
        res_none = calculate_url_risk(0.50, [], {}, threat_intel=None)
        res_err = calculate_url_risk(0.50, [], {}, threat_intel=ti_err)
        assert res_none["risk_score"] == res_err["risk_score"], f"Score changed for {st}"
        assert res_err["calculation_breakdown"]["threat_intel_points"] == 0


def test_risk_engine_clean_ti_preserves_local_score():
    """Clean TI (0 detections) leaves local risk score untouched."""
    ti_clean = {"summary": {"status": "success", "detections": 0, "risk_points": 0}}
    res_none = calculate_url_risk(0.40, [], {}, threat_intel=None)
    res_clean = calculate_url_risk(0.40, [], {}, threat_intel=ti_clean)
    assert res_none["risk_score"] == res_clean["risk_score"]
    assert res_clean["calculation_breakdown"]["threat_intel_points"] == 0


def test_risk_engine_ti_bounded_addition():
    """Valid positive detections apply strictly bounded points (+8 or +15)."""
    # 3 detections -> +8 points
    ti_susp = {"summary": {"status": "success", "detections": 3, "total_engines": 70}}
    res_base = calculate_url_risk(0.50, [], {}, threat_intel=None)
    res_susp = calculate_url_risk(0.50, [], {}, threat_intel=ti_susp)
    assert res_susp["risk_score"] == min(100, res_base["risk_score"] + 8)
    assert res_susp["calculation_breakdown"]["threat_intel_points"] == 8

    # 10 detections -> +15 points
    ti_mal = {"summary": {"status": "success", "detections": 10, "total_engines": 70}}
    res_mal = calculate_url_risk(0.50, [], {}, threat_intel=ti_mal)
    assert res_mal["risk_score"] == min(100, res_base["risk_score"] + 15)
    assert res_mal["calculation_breakdown"]["threat_intel_points"] == 15


def test_risk_engine_score_bounds_with_ti():
    """Final score never exceeds 100 or drops below 0 even with maximum TI points."""
    heavy_rules = [{"name": f"R{i}", "score_impact": 20, "description": ""} for i in range(10)]
    ti_max = {"summary": {"status": "success", "detections": 60, "total_engines": 70}}
    res = calculate_url_risk(1.0, heavy_rules, {}, threat_intel=ti_max)
    assert res["risk_score"] == 100
    assert res["risk_level"] == "Critical"

    res_min = calculate_url_risk(0.0, [], {}, threat_intel=None)
    assert res_min["risk_score"] == 0


def test_risk_engine_breakdown_contains_all_keys():
    """Breakdown includes existing keys and new threat_intel keys."""
    res = calculate_url_risk(0.5, [], {})
    bd = res["calculation_breakdown"]
    assert "ml_base_points" in bd
    assert "rule_points_applied" in bd
    assert "threat_intel_points" in bd
    assert "threat_intel_status" in bd
    assert "threat_intel_detections" in bd


# ─────────────────────────────────────────────────────────────────────────────
# 5. EXPLANATION BUILDER INTEGRATION TESTS
# ─────────────────────────────────────────────────────────────────────────────

def test_explanation_builder_includes_ti_field():
    """build_url_explanation preserves threat_intelligence in output."""
    features = {
        "url_length": 30, "num_dots": 1, "has_ip": 0, "has_at_symbol": 0,
        "has_double_slash": 0, "special_char_count": 0, "num_subdomains": 0,
        "has_https": 1, "domain_length": 10, "path_length": 15,
        "has_port": 0, "has_query": 0, "has_fragment": 0, "num_params": 0,
        "ratio_digits": 0.0, "ratio_letters": 0.9, "has_redirect": 0,
        "has_suspicious_tld": 0, "has_brand_keyword": 0, "has_hex_encoding": 0,
        "url_entropy": 2.5, "num_hyphens": 0, "num_underscores": 0,
        "path_depth": 1, "has_login_keyword": 0
    }
    ti_data = {
        "summary": {"status": "success", "detections": 4, "total_engines": 68}
    }
    risk_data = calculate_url_risk(0.4, [], features, threat_intel=ti_data)
    exp = build_url_explanation(
        url="https://example.com/login",
        features=features,
        ml_probability=0.4,
        ml_prediction="Legitimate",
        risk_data=risk_data,
        triggered_rules=[],
        threat_intel=ti_data
    )
    assert "threat_intelligence" in exp
    assert exp["threat_intelligence"] == ti_data
    assert exp["scan_type"] == "url"
    assert "what_does_this_mean" in exp

    # Timeline stage check
    stages = [s["stage"] for s in exp.get("investigation_stages", [])]
    assert any("Threat Intelligence" in s for s in stages)


def test_explanation_builder_none_ti_safe():
    """build_url_explanation executes safely when threat_intel is None."""
    features = {f: 0 for f in [
        "url_length", "num_dots", "has_ip", "has_at_symbol",
        "has_double_slash", "special_char_count", "num_subdomains",
        "has_https", "domain_length", "path_length",
        "has_port", "has_query", "has_fragment", "num_params",
        "ratio_digits", "ratio_letters", "has_redirect",
        "has_suspicious_tld", "has_brand_keyword", "has_hex_encoding",
        "url_entropy", "num_hyphens", "num_underscores",
        "path_depth", "has_login_keyword"
    ]}
    risk_data = calculate_url_risk(0.1, [], features)
    exp = build_url_explanation(
        url="https://legit.com",
        features=features,
        ml_probability=0.1,
        ml_prediction="Legitimate",
        risk_data=risk_data,
        triggered_rules=[],
        threat_intel=None
    )
    assert exp["threat_intelligence"] is None
    assert exp["scan_type"] == "url"


# ─────────────────────────────────────────────────────────────────────────────
# 6. PIPELINE INTEGRATION TESTS
# ─────────────────────────────────────────────────────────────────────────────

def test_url_analyzer_returns_threat_intelligence_field():
    """analyze_url returns threat_intelligence in its result dictionary."""
    from services.url_analyzer import analyze_url
    reset_threat_intel_service()

    mock_svc = MagicMock()
    mock_svc.lookup_url.return_value = {
        "enabled": False,
        "summary": {"status": "not_configured", "detections": 0, "risk_points": 0}
    }
    with patch("services.url_analyzer.get_threat_intel_service", return_value=mock_svc):
        res = analyze_url("https://example.com")
    assert res["success"] is True
    assert "threat_intelligence" in res
    assert "risk_score" in res
    assert "risk_level" in res
    assert "triggered_rules" in res
    assert "recommendation" in res


def test_url_analyzer_ti_failure_preserves_local_score():
    """If TI fails or times out, local risk score is completely preserved."""
    from services.url_analyzer import analyze_url
    reset_threat_intel_service()

    mock_svc_unconf = MagicMock()
    mock_svc_unconf.lookup_url.return_value = {
        "summary": {"status": "not_configured", "detections": 0, "risk_points": 0}
    }
    with patch("services.url_analyzer.get_threat_intel_service", return_value=mock_svc_unconf):
        res1 = analyze_url("https://example.com")

    mock_svc_err = MagicMock()
    mock_svc_err.lookup_url.return_value = {
        "summary": {"status": "timeout", "detections": 0, "risk_points": 0}
    }
    with patch("services.url_analyzer.get_threat_intel_service", return_value=mock_svc_err):
        res2 = analyze_url("https://example.com")

    assert res1["risk_score"] == res2["risk_score"]
    assert res1["risk_level"] == res2["risk_level"]


def test_message_analyzer_contains_threat_intelligence_field():
    """analyze_message returns threat_intelligence field."""
    from services.message_analyzer import analyze_message
    res = analyze_message("Urgent: your account is locked. Please review.")
    assert "threat_intelligence" in res
    assert "risk_score" in res
    assert "risk_level" in res
    assert "detected_indicators" in res


# ─────────────────────────────────────────────────────────────────────────────
# 7. SECURITY & INTEGRITY TESTS
# ─────────────────────────────────────────────────────────────────────────────

def test_dangerous_scheme_rejected_before_ti():
    """Dangerous URL schemes are blocked and do not perform TI lookups."""
    from services.url_analyzer import analyze_url
    mock_svc = MagicMock()
    with patch("services.url_analyzer.get_threat_intel_service", return_value=mock_svc):
        res = analyze_url("javascript:alert('xss')")
    assert res["success"] is False
    # TI service must never be queried for an invalid or dangerous scheme
    mock_svc.lookup_url.assert_not_called()


def test_vt_request_timeout_enforced():
    """VirusTotal provider passes timeout to requests.get."""
    p = VirusTotalProvider(api_key="KEY", timeout_sec=3.5)
    mock_resp = _mock_vt_response(200, {
        "data": {"attributes": {"last_analysis_stats": {"malicious": 0}}}
    })
    with patch("requests.get", return_value=mock_resp) as mock_get:
        p.lookup_url("https://example.com")
    assert mock_get.called
    kwargs = mock_get.call_args[1]
    assert "timeout" in kwargs
    assert kwargs["timeout"] == 3.5


# ─────────────────────────────────────────────────────────────────────────────
# 8. FLASK REST API CONTRACT TESTS
# ─────────────────────────────────────────────────────────────────────────────

def test_api_analyze_url_returns_ti_field():
    """POST /api/analyze-url returns threat_intelligence in JSON data payload."""
    from app import create_app
    app = create_app()
    app.config["TESTING"] = True
    client = app.test_client()

    mock_svc = MagicMock()
    mock_svc.lookup_url.return_value = {
        "summary": {"status": "not_configured", "detections": 0, "risk_points": 0}
    }
    with patch("services.url_analyzer.get_threat_intel_service", return_value=mock_svc):
        resp = client.post("/api/analyze-url", json={"url": "https://example.com"})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["success"] is True
    assert "threat_intelligence" in data["data"]
    assert "risk_score" in data["data"]
    assert "risk_level" in data["data"]


def test_api_analyze_message_returns_ti_field():
    """POST /api/analyze-message returns threat_intelligence in JSON data payload."""
    from app import create_app
    app = create_app()
    app.config["TESTING"] = True
    client = app.test_client()

    resp = client.post("/api/analyze-message", json={"message": "Friendly reminder for lunch today."})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["success"] is True
    assert "threat_intelligence" in data["data"]


def test_api_key_never_exposed_in_api_response():
    """API key is never reflected in the HTTP response body."""
    from app import create_app
    app = create_app()
    app.config["TESTING"] = True
    client = app.test_client()

    secret_key = "VIRUSTOTAL_SECRET_API_KEY_443"
    with patch.dict(os.environ, {"VIRUSTOTAL_API_KEY": secret_key}):
        resp = client.post("/api/analyze-url", json={"url": "https://example.com"})
    body = resp.get_data(as_text=True)
    assert secret_key not in body


if __name__ == "__main__":
    import pytest
    pytest.main([__file__, "-v"])

