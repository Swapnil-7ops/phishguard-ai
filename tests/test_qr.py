"""
tests/test_qr.py — Phase 10 QR / Quishing Detection Automated Test Suite

Covers:
  - Image decoding (valid QR, plain text, empty, corrupt, solid image, unsupported format)
  - Dangerous schemes (javascript:, data:, file:, vbscript:, about:)
  - Pipeline integration (URL analyzer reuse, 25 features, RF model, rules, risk engine, Phase 9 explanation)
  - Security & isolation (no outbound HTTP requests, no browser launching)
  - Database persistence (scan_type='qr', retrieval, fallback)
  - REST API endpoint (/api/analyze-qr)

All tests are written as pytest-standard test functions.
"""
import io
import sys
import os
import json
from unittest.mock import patch

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

import qrcode
from PIL import Image
from services.qr_service import decode_qr_image, process_qr_scan, _is_dangerous_scheme
from database.mongodb import save_scan, get_scan_history
from database.privacy import sanitize_scan_input


def _make_qr_bytes(data: str, fmt: str = "PNG", box_size: int = 8, border: int = 4) -> bytes:
    """Generate a valid QR code in memory and return raw bytes."""
    qr = qrcode.QRCode(box_size=box_size, border=border)
    qr.add_data(data)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white").convert("RGB")
    buf = io.BytesIO()
    img.save(buf, format=fmt)
    buf.seek(0)
    return buf.read()


def _make_solid_image_bytes(width: int = 150, height: int = 150, fmt: str = "PNG") -> bytes:
    """Generate a blank image with no QR code."""
    img = Image.new("RGB", (width, height), color=(255, 255, 255))
    buf = io.BytesIO()
    img.save(buf, format=fmt)
    buf.seek(0)
    return buf.read()


# ─────────────────────────────────────────────────────────────────────────────
# 1. DECODING & INPUT VALIDATION TESTS
# ─────────────────────────────────────────────────────────────────────────────

def test_1_valid_https_qr():
    """Decodes a QR containing a legitimate HTTPS URL."""
    b = _make_qr_bytes("https://legit-site.example.com/welcome")
    res = decode_qr_image(b)
    assert res["success"] is True
    assert "https://legit-site.example.com/welcome" in res["decoded_text"]
    assert res["qr_count"] == 1


def test_2_valid_http_qr():
    """Decodes a QR containing an HTTP URL."""
    b = _make_qr_bytes("http://legacy-site.example.org/path")
    res = decode_qr_image(b)
    assert res["success"] is True
    assert "http://legacy-site.example.org/path" in res["decoded_text"]


def test_3_suspicious_url_qr():
    """Decodes a QR containing an IP-based suspicious URL."""
    b = _make_qr_bytes("http://192.168.1.1/login.php")
    res = decode_qr_image(b)
    assert res["success"] is True
    assert "192.168.1.1" in res["decoded_text"]


def test_4_malformed_url_qr():
    """Decodes a malformed URL; pipeline handles it without crashing."""
    b = _make_qr_bytes("ht!tp://wrong:url@@not-valid")
    res = process_qr_scan(b)
    assert isinstance(res, dict)
    assert "success" in res


def test_5_plain_text_qr():
    """Plain-text QR payload is handled as informational text, not URL."""
    b = _make_qr_bytes("Call 1-800-PHISHME for prizes")
    res = process_qr_scan(b)
    assert res["success"] is True
    assert res["payload_type"] == "text"
    assert res["prediction"] == "Informational"
    assert res["risk_score"] == 0
    assert res["url_analysis"] is None


def test_6_empty_image_bytes():
    """Empty byte input returns controlled error."""
    res = decode_qr_image(b"")
    assert res["success"] is False
    assert res["decoded_text"] is None
    assert "No image data" in res["error"]


def test_7_corrupted_image_bytes():
    """Corrupt image returns controlled error without throwing exception."""
    res = decode_qr_image(b"Not An Image Header At All \x00\xff")
    assert res["success"] is False
    assert res["decoded_text"] is None
    assert res["error"] is not None


def test_8_unsupported_image_bytes():
    """Unsupported non-image file type returns controlled error."""
    res = decode_qr_image(b"%PDF-1.4 dummy pdf document data")
    assert res["success"] is False
    assert res["decoded_text"] is None


def test_9_oversized_image_handling():
    """Image with safe dimension boundary resize doesn't crash."""
    large_img = Image.new("RGB", (4200, 4200), color=(255, 255, 255))
    buf = io.BytesIO()
    large_img.save(buf, format="JPEG")
    res = decode_qr_image(buf.getvalue())
    assert isinstance(res, dict)
    assert res["success"] is False  # Blank image, no QR


def test_10_image_without_qr():
    """Image without any QR code returns controlled failure."""
    b = _make_solid_image_bytes()
    res = decode_qr_image(b)
    assert res["success"] is False
    assert res["qr_count"] == 0
    assert "No QR code could be recognized" in res["error"]


# ─────────────────────────────────────────────────────────────────────────────
# 2. DANGEROUS SCHEMES REJECTION TESTS
# ─────────────────────────────────────────────────────────────────────────────

def test_11_javascript_scheme_rejected():
    """javascript: QR payload is blocked with risk=100 and prediction=Blocked."""
    b = _make_qr_bytes("javascript:alert(document.cookie)")
    res = process_qr_scan(b)
    assert res["success"] is True
    assert res["payload_type"] == "dangerous_scheme"
    assert res["prediction"] == "Blocked"
    assert res["risk_score"] == 100
    assert res["risk_level"] == "Critical"
    assert res["url_analysis"] is None


def test_12_data_scheme_rejected():
    """data: QR payload is blocked immediately."""
    b = _make_qr_bytes("data:text/html,<script>alert(1)</script>")
    res = process_qr_scan(b)
    assert res["success"] is True
    assert res["payload_type"] == "dangerous_scheme"
    assert res["prediction"] == "Blocked"
    assert res["risk_score"] == 100


def test_13_file_scheme_rejected():
    """file: QR payload is blocked."""
    b = _make_qr_bytes("file:///etc/passwd")
    res = process_qr_scan(b)
    assert res["success"] is True
    assert res["payload_type"] == "dangerous_scheme"
    assert res["prediction"] == "Blocked"


def test_14_vbscript_scheme_rejected():
    """vbscript: QR payload is blocked."""
    b = _make_qr_bytes("vbscript:MsgBox('Phish')")
    res = process_qr_scan(b)
    assert res["success"] is True
    assert res["payload_type"] == "dangerous_scheme"
    assert res["prediction"] == "Blocked"


def test_15_about_scheme_rejected():
    """about: QR payload is blocked."""
    b = _make_qr_bytes("about:blank")
    res = process_qr_scan(b)
    assert res["success"] is True
    assert res["payload_type"] == "dangerous_scheme"
    assert res["prediction"] == "Blocked"


def test_15b_is_dangerous_scheme_helper():
    """Unit test for _is_dangerous_scheme helper function."""
    assert _is_dangerous_scheme("JAVASCRIPT:void(0)") is True
    assert _is_dangerous_scheme("data:application/json") is True
    assert _is_dangerous_scheme("FILE:///C:/secret.txt") is True
    assert _is_dangerous_scheme("https://google.com") is False
    assert _is_dangerous_scheme("http://example.com") is False


# ─────────────────────────────────────────────────────────────────────────────
# 3. PIPELINE INTEGRATION TESTS (URL ANALYZER REUSE)
# ─────────────────────────────────────────────────────────────────────────────

def test_16_decoded_url_reaches_existing_url_analyzer():
    """Decoded URL is processed by the URL analyzer and returns expected keys."""
    b = _make_qr_bytes("https://secure.paypal.com.account-update.xyz/login")
    res = process_qr_scan(b)
    assert res["success"] is True
    assert res["payload_type"] == "url"
    assert res["url_analysis"] is not None
    assert "prediction" in res["url_analysis"]


def test_17_existing_25_features_produced():
    """URL analysis produced from QR contains all 25 standard features."""
    b = _make_qr_bytes("https://example.com/test-feature-count")
    res = process_qr_scan(b)
    assert res["payload_type"] == "url"
    features = res["url_analysis"]["features"]
    assert len(features) == 25


def test_18_existing_random_forest_is_used():
    """URL analysis from QR reports the Random Forest model."""
    b = _make_qr_bytes("https://legit-site-test.com/path")
    res = process_qr_scan(b)
    assert res["url_analysis"]["model"] == "Random Forest"
    assert res["url_analysis"]["model_loaded"] is True


def test_19_existing_rules_are_used():
    """Suspicious QR URL triggers standard security rules (e.g. URL shortener / IP)."""
    b = _make_qr_bytes("http://192.168.1.1/admin-login")
    res = process_qr_scan(b)
    rule_ids = [r["rule_id"] for r in res["url_analysis"]["triggered_rules"]]
    assert "URL_IP" in rule_ids


def test_20_existing_risk_engine_is_used():
    """Risk breakdown is provided via calculation_breakdown."""
    b = _make_qr_bytes("https://paypal-security-update.com/verify")
    res = process_qr_scan(b)
    breakdown = res["url_analysis"]["calculation_breakdown"]
    assert "ml_base_points" in breakdown
    assert "rule_points_applied" in breakdown
    assert "formula" in breakdown


def test_21_phase_9_explanation_is_returned():
    """Result includes the full Phase 9 explanation dict."""
    b = _make_qr_bytes("https://github.com/login")
    res = process_qr_scan(b)
    explanation = res["url_analysis"]["explanation"]
    assert explanation["scan_type"] == "url"
    assert "investigation_stages" in explanation
    assert "feature_evidence" in explanation
    assert "risk_contribution" in explanation


def test_22_risk_remains_0_to_100():
    """Risk score is always bounded within [0, 100]."""
    for url in ["https://google.com", "http://192.168.1.1/evil", "javascript:alert(1)"]:
        b = _make_qr_bytes(url)
        res = process_qr_scan(b)
        score = res.get("risk_score")
        assert score is not None
        assert 0 <= score <= 100


# ─────────────────────────────────────────────────────────────────────────────
# 4. DATABASE & PERSISTENCE TESTS
# ─────────────────────────────────────────────────────────────────────────────

def test_23_qr_scan_persists_correctly():
    """save_scan persists with input_type='qr' and is retrievable via get_scan_history."""
    mock_analysis = {
        "prediction": "Phishing",
        "risk_score": 90,
        "risk_level": "Critical",
        "risk_level_display": "Critical Risk",
        "recommendation": "Do not open.",
        "triggered_rules": [],
        "reasons": ["Detected via QR code"],
        "features": {"length_url": 30},
        "ml_probability_estimate": 0.90,
        "model_loaded": True,
        "model": "Random Forest",
        "confidence": 0.90,
        "calculation_breakdown": {},
        "explanation": {},
    }
    scan_id = save_scan(
        input_type="qr",
        raw_input="https://qr-test-persistence.example.com",
        analysis_result=mock_analysis,
        model_version="1.0"
    )
    assert scan_id is not None

    records = get_scan_history(limit=50, offset=0, scan_type="qr")
    assert any(r.get("input_type") == "qr" or r.get("scan_type") == "qr" for r in records)


def test_24_fallback_persistence_works_for_qr():
    """In-memory persistence properly sanitizes QR raw_input credentials and tokens."""
    sanitized = sanitize_scan_input("https://user:pass@example.com/login?token=secret", "qr")
    assert "pass" not in sanitized
    assert "secret" not in sanitized
    assert "[REDACTED]" in sanitized


# ─────────────────────────────────────────────────────────────────────────────
# 5. SECURITY & NETWORK ISOLATION TESTS
# ─────────────────────────────────────────────────────────────────────────────

def test_25_no_outbound_http_requests():
    """CRITICAL SECURITY: QR scanning must NEVER make outbound HTTP requests."""
    b = _make_qr_bytes("https://malicious-destination-test.example.com")
    with patch("requests.get") as mock_get, \
         patch("requests.post") as mock_post, \
         patch("urllib.request.urlopen") as mock_urlopen:
        res = process_qr_scan(b)
        assert res["success"] is True
        mock_get.assert_not_called()
        mock_post.assert_not_called()
        mock_urlopen.assert_not_called()


def test_26_decoded_url_is_never_opened():
    """CRITICAL SECURITY: Decoded URL is never opened via browser or subprocess."""
    b = _make_qr_bytes("https://test-no-open.example.com")
    with patch("webbrowser.open", create=True) as mock_open, \
         patch("subprocess.Popen", create=True) as mock_sub:
        res = process_qr_scan(b)
        assert res["success"] is True
        mock_open.assert_not_called()
        mock_sub.assert_not_called()


def test_27_dangerous_scheme_does_not_reach_url_analyzer():
    """Dangerous schemes are rejected before reaching analyze_url."""
    b = _make_qr_bytes("javascript:fetch('https://attacker.com')")
    with patch("services.qr_service.analyze_url") as mock_analyze:
        res = process_qr_scan(b)
        assert res["payload_type"] == "dangerous_scheme"
        mock_analyze.assert_not_called()


# ─────────────────────────────────────────────────────────────────────────────
# 6. REST API INTEGRATION TESTS
# ─────────────────────────────────────────────────────────────────────────────

def test_28_api_analyze_qr_valid():
    """POST /api/analyze-qr with a valid QR returns HTTP 200 with result structure."""
    from app import app
    app.config["TESTING"] = True
    app.config["WTF_CSRF_ENABLED"] = False
    client = app.test_client()

    b = _make_qr_bytes("https://paypal.com")
    resp = client.post(
        "/api/analyze-qr",
        data={"image": (io.BytesIO(b), "test_qr.png", "image/png")},
        content_type="multipart/form-data"
    )
    assert resp.status_code == 200
    body = json.loads(resp.data)
    assert body["success"] is True
    assert body["data"]["qr_detected"] is True
    assert body["data"]["payload_type"] == "url"


def test_29_api_analyze_qr_missing_image_returns_400():
    """POST /api/analyze-qr without image returns 400."""
    from app import app
    client = app.test_client()
    resp = client.post("/api/analyze-qr", data={}, content_type="multipart/form-data")
    assert resp.status_code == 400
    body = json.loads(resp.data)
    assert body["success"] is False


def test_30_api_analyze_qr_corrupt_file_returns_error():
    """POST /api/analyze-qr with corrupt bytes returns controlled error."""
    from app import app
    client = app.test_client()
    resp = client.post(
        "/api/analyze-qr",
        data={"image": (io.BytesIO(b"corrupt junk"), "corrupt.png", "image/png")},
        content_type="multipart/form-data"
    )
    assert resp.status_code == 200
    body = json.loads(resp.data)
    assert body["data"]["success"] is False


def test_31_api_analyze_qr_url_analysis_fields_and_nonzero_risk():
    """
    Regression test: QR URL payload passes through existing URL analyzer and
    surfaces all URL analysis fields (including non-zero risk, prediction,
    rules, and explanation) without reverting to default 0 when TI is disabled.
    """
    from app import app
    app.config["TESTING"] = True
    app.config["WTF_CSRF_ENABLED"] = False
    client = app.test_client()

    payload = "https://example.test/verify-account-login"
    b = _make_qr_bytes(payload)

    resp = client.post(
        "/api/analyze-qr",
        data={"image": (io.BytesIO(b), "suspicious_qr.png", "image/png")},
        content_type="multipart/form-data"
    )
    assert resp.status_code == 200
    body = json.loads(resp.data)
    assert body["success"] is True

    data = body["data"]
    assert data["qr_detected"] is True
    assert data["payload_type"] == "url"
    assert data["decoded_url"] == payload

    # Must reuse URL analyzer and not return default 0 risk
    assert data["risk_score"] > 0
    assert data["risk_score"] == data["url_analysis"]["risk_score"]
    assert data["prediction"] == data["url_analysis"]["prediction"]
    assert data["risk_level"] in ("Low", "Medium", "High", "Critical")

    # URL analysis fields must be populated
    assert "prediction" in data
    assert "risk_score" in data
    assert "risk_level" in data
    assert "ml_probability" in data
    assert data["ml_probability"] is not None
    assert "recommendation" in data and len(data["recommendation"]) > 0
    assert "reasons" in data and len(data["reasons"]) > 0
    assert "triggered_rules" in data and len(data["triggered_rules"]) > 0
    assert "detected_indicators" in data
    assert "features" in data and len(data["features"]) == 25
    assert "calculation_breakdown" in data
    assert "explanation" in data and data["explanation"]["scan_type"] == "url"

    # Threat Intelligence is present and handled safely without breaking local scoring
    assert "threat_intelligence" in data
    assert data["threat_intelligence"]["summary"]["risk_points"] == 0 or isinstance(data["threat_intelligence"]["summary"]["risk_points"], (int, float))

