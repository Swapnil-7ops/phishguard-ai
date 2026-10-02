"""
tests/test_screenshot.py — Phase 12 Screenshot / Visual Phishing Detection Test Suite

Comprehensive testing for:
  1. Image validation & loading (formats, size bounds, corruption handling)
  2. OpenCV visual structure heuristics (input fields, buttons, layout complexity)
  3. Optional OCR text extraction & graceful degradation without Tesseract
  4. Text indicator scanning (credentials, urgency, financial, brand keywords)
  5. URL and domain extraction from text
  6. Brand-domain correlation and mismatch detection
  7. Risk engine screenshot risk calculation and bounding caps
  8. Phase 9 structured explanation generation
  9. Multi-modal pipeline integration (URL analyzer and Threat Intelligence reuse)
 10. Security & privacy guarantees (in-memory processing, zero outbound requests, privacy sanitization)
 11. REST API endpoint contract (/api/analyze-screenshot)
"""
import io
import sys
import os
import json
from unittest.mock import patch, MagicMock

import pytest
from PIL import Image, ImageDraw

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from services.screenshot_service import (
    validate_and_load_image,
    analyze_visual_structure,
    extract_ocr_text,
    extract_text_indicators,
    extract_domains_and_urls,
    correlate_brand_and_domain,
    process_screenshot_analysis,
)
from services.risk_engine import calculate_screenshot_risk
from services.explanation_builder import build_screenshot_explanation
from app import create_app


# ─────────────────────────────────────────────────────────────────────────────
# Synthetic Test Image Helpers (Generated strictly in-memory)
# ─────────────────────────────────────────────────────────────────────────────

def _make_blank_image_bytes(width: int = 400, height: int = 300, fmt: str = "PNG") -> bytes:
    """Create a plain flat background image."""
    img = Image.new("RGB", (width, height), color=(250, 245, 235))
    buf = io.BytesIO()
    img.save(buf, format=fmt)
    return buf.getvalue()


def _make_login_form_image_bytes(width: int = 500, height: int = 400, fmt: str = "PNG") -> bytes:
    """Create a synthetic login form with 2 input boxes and 1 button."""
    img = Image.new("RGB", (width, height), color=(240, 240, 240))
    draw = ImageDraw.Draw(img)

    # Form container
    draw.rectangle([50, 40, 450, 360], fill=(255, 255, 255), outline=(180, 180, 180), width=2)
    # Input field 1 (Username)
    draw.rectangle([90, 100, 410, 140], fill=(255, 255, 255), outline=(50, 50, 50), width=2)
    # Input field 2 (Password)
    draw.rectangle([90, 170, 410, 210], fill=(255, 255, 255), outline=(50, 50, 50), width=2)
    # Submit button
    draw.rectangle([120, 250, 380, 295], fill=(30, 90, 200), outline=(20, 70, 160), width=2)

    buf = io.BytesIO()
    img.save(buf, format=fmt)
    return buf.getvalue()


def _make_corrupt_bytes() -> bytes:
    """Return invalid/corrupted non-image bytes."""
    return b"NOT_A_VALID_IMAGE_HEADER_BYTES_123456789"


# ─────────────────────────────────────────────────────────────────────────────
# 1. Image Validation & Loading
# ─────────────────────────────────────────────────────────────────────────────

def test_validate_and_load_valid_png():
    """Valid in-memory PNG loads successfully into RGB Pillow Image."""
    b = _make_blank_image_bytes(fmt="PNG")
    img = validate_and_load_image(b, "screenshot.png")
    assert isinstance(img, Image.Image)
    assert img.mode == "RGB"
    assert img.size == (400, 300)


def test_validate_and_load_valid_jpeg():
    """Valid in-memory JPEG loads successfully."""
    b = _make_blank_image_bytes(fmt="JPEG")
    img = validate_and_load_image(b, "capture.jpg")
    assert isinstance(img, Image.Image)
    assert img.mode == "RGB"


def test_validate_and_load_valid_webp():
    """Valid in-memory WEBP loads successfully."""
    b = _make_blank_image_bytes(fmt="WEBP")
    img = validate_and_load_image(b, "preview.webp")
    assert isinstance(img, Image.Image)
    assert img.mode == "RGB"


def test_validate_and_load_disallowed_extension():
    """Disallowed extension (e.g. .exe, .sh, .txt) raises ValueError."""
    b = _make_blank_image_bytes()
    with pytest.raises(ValueError, match="Unsupported image format"):
        validate_and_load_image(b, "malware.exe")


def test_validate_and_load_corrupt_bytes():
    """Truncated or corrupted bytes raise ValueError on verification."""
    b = _make_corrupt_bytes()
    with pytest.raises(ValueError, match="Unable to read image"):
        validate_and_load_image(b, "corrupt.png")


def test_validate_and_load_oversized_bytes():
    """Payload exceeding 10MB limit raises ValueError."""
    huge_bytes = b"0" * (10 * 1024 * 1024 + 1024)
    with pytest.raises(ValueError, match="exceeds maximum allowed size"):
        validate_and_load_image(huge_bytes, "huge.png")


# ─────────────────────────────────────────────────────────────────────────────
# 2. OpenCV Visual Structure Analysis
# ─────────────────────────────────────────────────────────────────────────────

def test_visual_structure_blank_image():
    """A completely blank flat image detects minimal interactive elements."""
    img = Image.open(io.BytesIO(_make_blank_image_bytes()))
    res = analyze_visual_structure(img)
    assert "input_fields" in res
    assert "buttons" in res
    assert "contour_count" in res
    assert "visual_points" in res
    assert res["input_fields"] == 0
    assert res["buttons"] == 0
    assert res["visual_points"] == 0


def test_visual_structure_login_form():
    """Synthetic login form with 2 inputs and button triggers visual score."""
    img = Image.open(io.BytesIO(_make_login_form_image_bytes()))
    res = analyze_visual_structure(img)
    assert res["input_fields"] >= 1
    assert res["contour_count"] > 0
    assert res["visual_points"] > 0
    assert res["visual_points"] <= 35


def test_visual_points_strictly_bounded_at_35():
    """Visual points cannot exceed maximum bound of 35."""
    img = Image.open(io.BytesIO(_make_login_form_image_bytes()))
    res = analyze_visual_structure(img)
    assert res["visual_points"] <= 35


# ─────────────────────────────────────────────────────────────────────────────
# 3. Optional OCR & Graceful Degradation
# ─────────────────────────────────────────────────────────────────────────────

def test_ocr_graceful_fallback_when_unavailable():
    """When OCR is not available, returns empty string and False without crashing."""
    img = Image.open(io.BytesIO(_make_blank_image_bytes()))
    with patch("services.screenshot_service._OCR_AVAILABLE", False):
        text, available = extract_ocr_text(img)
        assert text == ""
        assert available is False


def test_ocr_extracts_mocked_text():
    """When OCR engine runs, returns extracted string and True."""
    img = Image.open(io.BytesIO(_make_blank_image_bytes()))
    mock_tess = MagicMock()
    mock_tess.image_to_string.return_value = "Sign in to your Microsoft account"
    with patch("services.screenshot_service._OCR_AVAILABLE", True), \
         patch("services.screenshot_service.pytesseract", mock_tess):
        text, available = extract_ocr_text(img)
        assert "Microsoft" in text
        assert available is True


def test_ocr_exception_returns_false_safely():
    """If pytesseract throws an error, function returns ('', False) safely."""
    img = Image.open(io.BytesIO(_make_blank_image_bytes()))
    mock_tess = MagicMock()
    mock_tess.image_to_string.side_effect = RuntimeError("Tesseract died")
    with patch("services.screenshot_service._OCR_AVAILABLE", True), \
         patch("services.screenshot_service.pytesseract", mock_tess):
        text, available = extract_ocr_text(img)
        assert text == ""
        assert available is False



# ─────────────────────────────────────────────────────────────────────────────
# 4. Text Indicator Detection
# ─────────────────────────────────────────────────────────────────────────────

def test_extract_text_indicators_credential():
    """Credential keywords (password, login, sign in) are categorized."""
    raw = "Please enter your password and username to sign in."
    inds = extract_text_indicators(raw)
    assert "credential" in inds
    assert "password" in inds["credential"]
    assert "username" in inds["credential"]


def test_extract_text_indicators_urgency():
    """Urgency keywords (immediately, urgent, asap) are detected."""
    raw = "Your account will be suspended. Take immediate action now or immediately."
    inds = extract_text_indicators(raw)
    assert "urgency" in inds
    assert any(w in inds["urgency"] for w in ["immediately", "now", "immediate action"])


def test_extract_text_indicators_financial():
    """Financial keywords (bank, credit, card, payment) are detected."""
    raw = "Update your bank credit card details to complete payment."
    inds = extract_text_indicators(raw)
    assert "financial" in inds
    assert "bank" in inds["financial"]
    assert "credit" in inds["financial"]


def test_extract_text_indicators_brand():
    """Major brand names (PayPal, Google, Microsoft, Apple) are recognized."""
    raw = "Security notification from PayPal and Microsoft Defender."
    inds = extract_text_indicators(raw)
    assert "brand" in inds
    assert "paypal" in inds["brand"]
    assert "microsoft" in inds["brand"]


def test_extract_text_indicators_benign_text():
    """Clean benign text returns empty dictionary."""
    raw = "The quick brown fox jumps over the lazy dog."
    inds = extract_text_indicators(raw)
    assert inds == {}


# ─────────────────────────────────────────────────────────────────────────────
# 5. URL and Domain Extraction
# ─────────────────────────────────────────────────────────────────────────────

def test_extract_domains_and_urls_full_url():
    """Extracts standard HTTP and HTTPS URLs."""
    raw = "Visit our portal at https://secure-login.example.com/auth?token=123"
    urls = extract_domains_and_urls(raw)
    assert any("https://secure-login.example.com" in u for u in urls)


def test_extract_domains_and_urls_bare_domain():
    """Extracts bare domain names without http prefix."""
    raw = "Hosted on malicious-portal.tk for verification."
    urls = extract_domains_and_urls(raw)
    assert any("malicious-portal.tk" in u for u in urls)


def test_extract_domains_and_urls_none():
    """Text without URLs returns empty list."""
    raw = "Welcome to the corporate presentation on cybersecurity awareness."
    urls = extract_domains_and_urls(raw)
    assert urls == []


# ─────────────────────────────────────────────────────────────────────────────
# 6. Brand-Domain Correlation
# ─────────────────────────────────────────────────────────────────────────────

def test_brand_domain_mismatch_detected():
    """Brand detected in text (e.g. PayPal) but domain is deceptive (paypa1.tk)."""
    brands = ["paypal"]
    urls = ["https://paypa1-secure-auth.tk/login"]
    pts = correlate_brand_and_domain(brands, urls)
    assert pts == 20


def test_brand_domain_consistent():
    """Brand detected in text (PayPal) matches domain (paypal.com)."""
    brands = ["paypal"]
    urls = ["https://www.paypal.com/signin"]
    pts = correlate_brand_and_domain(brands, urls)
    assert pts == 0


def test_brand_domain_no_brands_or_no_urls():
    """Zero mismatch penalty when no brands or no URLs exist."""
    assert correlate_brand_and_domain([], ["https://example.com"]) == 0
    assert correlate_brand_and_domain(["google"], []) == 0
    assert correlate_brand_and_domain([], []) == 0


# ─────────────────────────────────────────────────────────────────────────────
# 7. Risk Engine calculate_screenshot_risk
# ─────────────────────────────────────────────────────────────────────────────

def test_calculate_screenshot_risk_all_zero():
    """Clean screenshot yields 0 risk and Low risk level."""
    res = calculate_screenshot_risk(visual_points=0, text_points=0, mismatch_points=0, url_cascade_points=0)
    assert res["risk_score"] == 0
    assert res["risk_level"] == "Low"
    assert "calculation_breakdown" in res


def test_calculate_screenshot_risk_bounding_caps():
    """Each individual component is strictly capped to its assigned ceiling."""
    res = calculate_screenshot_risk(
        visual_points=100,      # Cap: 35
        text_points=100,        # Cap: 25
        mismatch_points=100,    # Cap: 20
        url_cascade_points=100  # Cap: 20 (scaled 20% of 100)
    )
    bd = res["calculation_breakdown"]
    assert bd["visual_points"] == 35
    assert bd["text_points"] == 25
    assert bd["mismatch_points"] == 20
    assert bd["url_cascade_points"] == 20
    assert res["risk_score"] == 100
    assert res["risk_level"] == "Critical"


def test_calculate_screenshot_risk_partial_components():
    """Partial risk scoring produces appropriate categorical level."""
    res = calculate_screenshot_risk(visual_points=20, text_points=15, mismatch_points=0, url_cascade_points=0)
    assert res["risk_score"] == 35
    assert res["risk_level"] == "Medium"


def test_calculate_screenshot_risk_high_threshold():
    """Score 65 falls into High category."""
    res = calculate_screenshot_risk(visual_points=25, text_points=20, mismatch_points=20, url_cascade_points=0)
    assert res["risk_score"] == 65
    assert res["risk_level"] == "High"


# ─────────────────────────────────────────────────────────────────────────────
# 8. Phase 9 Explanation Generation
# ─────────────────────────────────────────────────────────────────────────────

def test_build_screenshot_explanation_structure():
    """Explanation builder returns structured dictionary matching Phase 9 conventions."""
    vis = {"input_fields": 2, "buttons": 1, "contour_count": 12, "visual_points": 20}
    bd = {
        "visual_points": 20, "visual_max": 35,
        "text_points": 10, "text_max": 25,
        "mismatch_points": 0, "mismatch_max": 20,
        "url_cascade_points": 0, "url_cascade_max": 20,
        "formula": "Final Risk Score = 30/100",
        "transparency_note": "Score transparency"
    }

    exp = build_screenshot_explanation(
        visual_results=vis,
        ocr_text="Login to your account",
        url_analysis=None,
        ti_data=None,
        risk_breakdown=bd,
    )

    assert exp["scan_type"] == "screenshot"
    assert "summary" in exp
    assert "visual_evidence" in exp
    assert "ocr_evidence" in exp
    assert "risk_contribution" in exp
    assert "investigation_stages" in exp
    assert exp["visual_evidence"]["input_fields_detected"] == 2
    assert exp["visual_evidence"]["buttons_detected"] == 1
    assert exp["ocr_evidence"]["available"] is True


def test_build_screenshot_explanation_ocr_unavailable_timeline():
    """Timeline accurately records OCR unavailable stage when OCR is offline."""
    vis = {"input_fields": 0, "buttons": 0, "contour_count": 2, "visual_points": 0}
    bd = {"visual_points": 0, "text_points": 0, "mismatch_points": 0, "url_cascade_points": 0}

    exp = build_screenshot_explanation(
        visual_results=vis,
        ocr_text=None,
        url_analysis=None,
        ti_data=None,
        risk_breakdown=bd,
    )
    stages = [s["stage"] for s in exp["investigation_stages"]]
    assert "OCR Text Extraction" in stages
    ocr_stage = [s for s in exp["investigation_stages"] if s["stage"] == "OCR Text Extraction"][0]
    assert "not available" in ocr_stage["detail"]


# ─────────────────────────────────────────────────────────────────────────────
# 9. Pipeline Orchestration & Multi-Modal Linkage
# ─────────────────────────────────────────────────────────────────────────────

def test_process_screenshot_analysis_clean_image():
    """Full pipeline with clean flat image returns complete valid envelope."""
    b = _make_blank_image_bytes()
    with patch("services.screenshot_service.extract_ocr_text", return_value=("", False)):
        res = process_screenshot_analysis(b, "clean.png")

    assert res["success"] is True
    assert res["prediction"] in ["legitimate", "suspicious", "phishing"]
    assert "risk_score" in res
    assert "visual_analysis" in res
    assert "explanation" in res
    assert res["ocr_available"] is False


def test_process_screenshot_analysis_with_mocked_ocr_and_url():
    """Pipeline with extracted URL cascades into URL Analyzer and Threat Intelligence."""
    b = _make_login_form_image_bytes()
    mock_ocr = "Please login immediately with your password at https://bank-verify.tk/login"

    mock_url_result = {
        "success": True,
        "input_url": "https://bank-verify.tk/login",
        "normalized_url": "https://bank-verify.tk/login",
        "risk_score": 75,
        "risk_level": "High",
        "prediction": "Phishing",
        "threat_intelligence": {
            "enabled": True,
            "summary": {"status": "success", "detections": 3, "total_engines": 70, "malicious": True}
        }
    }

    with patch("services.screenshot_service.extract_ocr_text", return_value=(mock_ocr, True)):
        with patch("services.url_analyzer.analyze_url", return_value=mock_url_result):
            res = process_screenshot_analysis(b, "phish_login.png")

    assert res["success"] is True
    assert res["ocr_available"] is True
    assert len(res["extracted_urls"]) >= 1
    assert res["url_analysis"] is not None
    assert res["risk_score"] > 20
    assert "explanation" in res
    assert res["explanation"]["threat_intelligence"] is not None


# ─────────────────────────────────────────────────────────────────────────────
# 10. Security & Privacy Guarantees
# ─────────────────────────────────────────────────────────────────────────────

def test_security_never_makes_outbound_requests_to_target():
    """Verifies that no sockets or HTTP clients connect to target extracted URLs."""
    b = _make_blank_image_bytes()
    mock_ocr = "Navigate to http://198.51.100.25/evil"

    with patch("urllib.request.urlopen") as mock_urlopen, \
         patch("http.client.HTTPConnection.connect") as mock_conn:
        with patch("services.screenshot_service.extract_ocr_text", return_value=(mock_ocr, True)):
            res = process_screenshot_analysis(b, "test.png")

        # Zero socket connections made to target URL
        mock_urlopen.assert_not_called()
        mock_conn.assert_not_called()


def test_security_screenshot_never_written_to_disk():
    """Processing creates no persistent temporary image files on disk."""
    import tempfile
    b = _make_blank_image_bytes()
    before_files = set(os.listdir(tempfile.gettempdir()))

    with patch("services.screenshot_service.extract_ocr_text", return_value=("", False)):
        process_screenshot_analysis(b, "memory_check.png")

    after_files = set(os.listdir(tempfile.gettempdir()))
    # No new leaked image files created in tempdir
    new_files = after_files - before_files
    image_leaks = [f for f in new_files if f.endswith(('.png', '.jpg', '.jpeg', '.webp'))]
    assert len(image_leaks) == 0


# ─────────────────────────────────────────────────────────────────────────────
# 11. REST API Endpoint Tests (/api/analyze-screenshot)
# ─────────────────────────────────────────────────────────────────────────────

def _get_test_client():
    app = create_app()
    app.config["TESTING"] = True
    return app.test_client()


@pytest.fixture
def client():
    return _get_test_client()


def test_api_analyze_screenshot_success(client=None):
    """POST /api/analyze-screenshot with valid image returns HTTP 200 and data."""
    c = client or _get_test_client()
    b = _make_blank_image_bytes()
    data = {
        "image": (io.BytesIO(b), "test.png")
    }
    with patch("services.screenshot_service.extract_ocr_text", return_value=("", False)):
        res = c.post("/api/analyze-screenshot", data=data, content_type="multipart/form-data")

    assert res.status_code == 200
    json_data = res.get_json()
    assert json_data["success"] is True
    assert "data" in json_data
    assert "risk_score" in json_data["data"]
    assert "visual_analysis" in json_data["data"]
    assert "explanation" in json_data["data"]


def test_api_analyze_screenshot_missing_field(client=None):
    """POST /api/analyze-screenshot without 'image' field returns HTTP 400."""
    c = client or _get_test_client()
    res = c.post("/api/analyze-screenshot", data={}, content_type="multipart/form-data")
    assert res.status_code == 400
    assert res.get_json()["success"] is False


def test_api_analyze_screenshot_empty_filename(client=None):
    """POST /api/analyze-screenshot with empty file returns HTTP 400."""
    c = client or _get_test_client()
    data = {
        "image": (io.BytesIO(b""), "")
    }
    res = c.post("/api/analyze-screenshot", data=data, content_type="multipart/form-data")
    assert res.status_code == 400
    assert res.get_json()["success"] is False


def test_api_analyze_screenshot_disallowed_type(client=None):
    """POST /api/analyze-screenshot with unsupported extension returns HTTP 400."""
    c = client or _get_test_client()
    data = {
        "image": (io.BytesIO(b"hello"), "script.py")
    }
    res = c.post("/api/analyze-screenshot", data=data, content_type="multipart/form-data")
    assert res.status_code == 400
    assert res.get_json()["success"] is False


def test_api_analyze_screenshot_corrupt_image(client=None):
    """POST /api/analyze-screenshot with corrupt image returns HTTP 400."""
    c = client or _get_test_client()
    data = {
        "image": (io.BytesIO(_make_corrupt_bytes()), "corrupt.png")
    }
    res = c.post("/api/analyze-screenshot", data=data, content_type="multipart/form-data")
    assert res.status_code == 400
    assert res.get_json()["success"] is False


def test_api_analyze_screenshot_persistence_scan_id(client=None):
    """POST /api/analyze-screenshot returns a persisted scan_id."""
    c = client or _get_test_client()
    b = _make_blank_image_bytes()
    data = {
        "image": (io.BytesIO(b), "test_persist.png")
    }
    with patch("services.screenshot_service.extract_ocr_text", return_value=("", False)):
        res = c.post("/api/analyze-screenshot", data=data, content_type="multipart/form-data")

    assert res.status_code == 200
    json_data = res.get_json()
    assert "scan_id" in json_data["data"]
    assert json_data["data"]["scan_id"] is not None

