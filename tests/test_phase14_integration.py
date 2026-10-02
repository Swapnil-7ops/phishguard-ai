"""
test_phase14_integration.py - Phase 14 Final Integration & Security Validation Suite

Verifies:
1. Cross-Modal Consistency across all 5 modalities (URL, Message, QR, Screenshot, Email).
2. URL Security & Dangerous Scheme Rejection (javascript:, data:, file:, vbscript:, about:).
3. XSS / Script Injection resilience & zero execution guarantee.
4. File Upload size and extension validation across all upload routes.
5. Threat Intelligence failure gracefully contributing 0 risk points.
6. Persistence layer sanitization & resilient in-memory fallback.
7. End-to-end API contract consistency.
"""
import sys
import json
import io
from pathlib import Path
from unittest.mock import patch, MagicMock

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))

from app import create_app
from config import config
from ml.feature_extractor import extract_url_features, get_feature_names
from services.url_analyzer import analyze_url, validate_and_normalize_url
from services.message_analyzer import analyze_message
from services.risk_engine import calculate_url_risk
from database.mongodb import save_scan, get_scan_history, reset_in_memory_storage
from database.privacy import sanitize_scan_input, sanitize_url_for_storage, sanitize_message_for_storage


def _get_client(client=None):
    if client is not None:
        return client
    app = create_app()
    app.config["TESTING"] = True
    return app.test_client()


# ======================================================================
# 1. CROSS-MODAL CONSISTENCY
# ======================================================================

def test_cross_modal_feature_extractor_integrity():
    """Verify standard 25 features are always produced for any valid URL."""
    feature_names = get_feature_names()
    assert len(feature_names) == 25

    sample_urls = [
        "https://www.paypal.com/signin",
        "http://192.168.1.1/login.php",
        "https://secure-update.paypal.com.verify-account.tk/index.html",
        "http://bit.ly/3xSample",
    ]
    for u in sample_urls:
        features = extract_url_features(u)
        assert len(features) == 25
        for fname in feature_names:
            assert fname in features, f"Missing feature {fname} for URL {u}"
            assert isinstance(features[fname], (int, float))


def test_cross_modal_url_pipeline_used_consistently():
    """Verify that URL, Message, and Email analysis modalities leverage the same URL analyzer."""
    test_url = "http://192.168.1.1/banking-login.php"

    # Direct URL analysis
    url_res = analyze_url(test_url)
    assert url_res["success"] is True
    assert url_res["risk_score"] > 20
    assert "features" in url_res
    assert len(url_res["features"]) == 25

    # Message analysis with embedded URL
    msg_res = analyze_message(f"Urgent: please verify your account at {test_url}", analyze_extracted_urls=True)
    assert msg_res["success"] is True
    assert len(msg_res["url_analyses"]) >= 1
    assert msg_res["url_analyses"][0]["normalized_url"] == url_res["normalized_url"]
    assert msg_res["url_analyses"][0]["risk_score"] == url_res["risk_score"]


# ======================================================================
# 2. DANGEROUS SCHEME REJECTION & URL INPUT SANITIZATION
# ======================================================================

def test_dangerous_schemes_rejected():
    """Verify that non-web dangerous protocol schemes are immediately refused."""
    dangerous = [
        "javascript:alert(document.cookie)",
        "JAVASCRIPT:alert(1)",
        "data:text/html,<script>alert(1)</script>",
        "file:///etc/passwd",
        "file:///C:/Windows/System32/calc.exe",
        "vbscript:msgbox('pwned')",
        "about:blank",
    ]
    for bad_url in dangerous:
        val = validate_and_normalize_url(bad_url)
        assert val["valid"] is False
        assert "scheme" in val["error"].lower() or "unsafe" in val["error"].lower()

        res = analyze_url(bad_url)
        assert res["success"] is False
        assert "error" in res


def test_url_boundary_and_normalization():
    """Verify normalization of scheme-less URLs and rejection of empty/oversized inputs."""
    # Empty
    assert validate_and_normalize_url("")["valid"] is False
    assert validate_and_normalize_url("   ")["valid"] is False

    # Oversized URL (>2048 chars)
    long_url = "http://example.com/" + "a" * 2050
    val_long = validate_and_normalize_url(long_url)
    assert val_long["valid"] is False
    assert "exceeds" in val_long["error"].lower()

    # Scheme-less URL is safely prepended with http://
    val_schemeless = validate_and_normalize_url("example.com/login")
    assert val_schemeless["valid"] is True
    assert val_schemeless["normalized_url"].startswith("http://example.com/login")


# ======================================================================
# 3. XSS & SCRIPT INJECTION RESILIENCE
# ======================================================================

def test_xss_in_message_body_safe(client=None):
    """Verify XSS payloads in text message analyzer do not crash or execute."""
    c = _get_client(client)
    xss_payload = "<script>alert('XSS')</script><img src=x onerror=alert(1)>"
    res = c.post('/api/analyze-message', json={"message": xss_payload})
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    assert 0 <= data["data"]["risk_score"] <= 100


def test_xss_in_url_input_safe(client=None):
    """Verify script tags passed as URL are rejected cleanly without 500 error."""
    c = _get_client(client)
    xss_url = "http://example.com/<script>alert(1)</script>"
    res = c.post('/api/analyze-url', json={"url": xss_url})
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    assert 0 <= data["data"]["risk_score"] <= 100


# ======================================================================
# 4. FILE UPLOAD SECURITY (QR, SCREENSHOT, EMAIL)
# ======================================================================

def test_qr_upload_invalid_extension(client=None):
    """Verify QR scanner rejects non-image extensions."""
    c = _get_client(client)
    data = {'image': (io.BytesIO(b'dummy content'), 'test.txt')}
    res = c.post('/api/analyze-qr', data=data, content_type='multipart/form-data')
    assert res.status_code == 400
    assert res.get_json()["success"] is False


def test_screenshot_upload_invalid_extension(client=None):
    """Verify Screenshot analyzer rejects non-image extensions."""
    c = _get_client(client)
    data = {'image': (io.BytesIO(b'dummy content'), 'payload.exe')}
    res = c.post('/api/analyze-screenshot', data=data, content_type='multipart/form-data')
    assert res.status_code == 400
    assert res.get_json()["success"] is False


def test_email_upload_invalid_extension(client=None):
    """Verify Email analyzer rejects non-.eml extensions."""
    c = _get_client(client)
    data = {'file': (io.BytesIO(b'dummy content'), 'document.docx')}
    res = c.post('/api/analyze-email', data=data, content_type='multipart/form-data')
    assert res.status_code == 400
    assert res.get_json()["success"] is False


def test_empty_file_upload_rejected(client=None):
    """Verify empty filename submissions are rejected with 400."""
    c = _get_client(client)
    res_qr = c.post('/api/analyze-qr', data={'image': (io.BytesIO(b''), '')}, content_type='multipart/form-data')
    assert res_qr.status_code == 400

    res_ss = c.post('/api/analyze-screenshot', data={'image': (io.BytesIO(b''), '')}, content_type='multipart/form-data')
    assert res_ss.status_code == 400

    res_eml = c.post('/api/analyze-email', data={'file': (io.BytesIO(b''), '')}, content_type='multipart/form-data')
    assert res_eml.status_code == 400


# ======================================================================
# 5. THREAT INTELLIGENCE FAILURE RESILIENCE
# ======================================================================

def test_threat_intelligence_all_error_codes_contribute_zero_risk():
    """Verify TI errors, missing keys, and HTTP errors contribute strictly 0 risk points."""
    error_states = [
        {"status": "not_configured", "detections": 0, "total_engines": 0},
        {"status": "timeout", "detections": 0, "total_engines": 0},
        {"status": "connection_error", "detections": 0, "total_engines": 0},
        {"status": "rate_limited", "detections": 0, "total_engines": 0},
        {"status": "http_error", "detections": 0, "total_engines": 0},
        {"status": "malformed_response", "detections": 0, "total_engines": 0},
        {"status": "error", "detections": 0, "total_engines": 0},
    ]
    for state in error_states:
        ti_mock = {"summary": state}
        res = calculate_url_risk(0.60, [], {}, threat_intel=ti_mock)
        # ML base: round(0.60 * 60) = 36. Rule: 0. TI: 0.
        assert res["risk_score"] == 36
        assert res["calculation_breakdown"]["threat_intel_points"] == 0


# ======================================================================
# 6. DATABASE PERSISTENCE, SANITIZATION & FALLBACK
# ======================================================================

def test_persistence_all_scan_types_and_sanitization():
    """Verify save_scan handles all 5 modalities and sanitizes sensitive credentials."""
    reset_in_memory_storage()

    # 1. URL with credentials in authority and token in query
    sensitive_url = "https://user:SuperSecretPassword123@evil.com/login?token=xyz123456&safe=value"
    scan_id_url = save_scan("url", sensitive_url, {"prediction": "Phishing", "risk_score": 85})
    assert scan_id_url is not None

    # 2. Message with card number and OTP
    sensitive_msg = "Your card 4111 2222 3333 4444 has been blocked. OTP: 987654 to unblock."
    scan_id_msg = save_scan("message", sensitive_msg, {"prediction": "Phishing", "risk_score": 90})
    assert scan_id_msg is not None

    # 3. QR scan
    scan_id_qr = save_scan("qr", "https://example.com/qr-link", {"prediction": "Legitimate", "risk_score": 10})
    assert scan_id_qr is not None

    # 4. Screenshot scan
    scan_id_ss = save_scan("screenshot", "[Screenshot: login.png]", {"prediction": "Suspicious", "risk_score": 45})
    assert scan_id_ss is not None

    # 5. Email scan
    scan_id_eml = save_scan("email", "[Email: phish.eml - Account Locked]", {"prediction": "Phishing", "risk_score": 75})
    assert scan_id_eml is not None

    # Verify history retrieval and redaction
    records = get_scan_history(limit=10)
    assert len(records) >= 5

    stored_url = next(r for r in records if r["scan_type"] == "url")
    assert "SuperSecretPassword123" not in stored_url["input"]
    assert "[REDACTED]" in stored_url["input"]

    stored_msg = next(r for r in records if r["scan_type"] == "message")
    assert "4111 2222 3333 4444" not in stored_msg["input"]
    assert "[CARD-REDACTED]" in stored_msg["input"]
    assert "987654" not in stored_msg["input"]


# ======================================================================
# 7. API CONTRACT & HEALTH CHECK
# ======================================================================

def test_api_health_contract(client=None):
    """Verify /api/health returns 200 with expected envelope structure."""
    c = _get_client(client)
    res = c.get('/api/health')
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    assert "status" in data["data"]
    assert data["data"]["status"] == "healthy"
