"""
screenshot_service.py - Lightweight Screenshot Visual Phishing Analysis Service

WHAT: Accepts uploaded screenshots and applies local OpenCV + Pillow visual
      heuristic analysis to detect phishing indicators without external APIs.
WHY:  Provides visual phishing detection that works offline — no API key
      or internet connectivity required.
HOW:
  1. Validate and decode image via Pillow.
  2. Detect form fields, buttons, and layout clutter via OpenCV contour analysis.
  3. Optionally extract text via pytesseract OCR.
  4. Scan extracted text for credential, urgency, financial, and brand keywords.
  5. Extract URLs/domains from OCR text.
  6. Correlate detected brand keywords against extracted domains (mismatch check).
  7. If URLs found, cascade to existing URL Analyzer (static analysis only).
  8. Calculate composite risk via risk_engine.calculate_screenshot_risk().
  9. Build Phase 9 explanation via explanation_builder.build_screenshot_explanation().
SECURITY:
  - NEVER fetches, visits, or opens URLs extracted from screenshots.
  - Processes images in-memory only — never written to disk.
  - All URL cascade analysis is static/lexical only.
LIMITATIONS:
  - Visual heuristics may miss stylized or obfuscated form elements.
  - OCR depends on pytesseract + Tesseract binary being installed.
  - Brand-domain correlation uses a static keyword list.
  - Single-image analysis per request.
"""

import io
import re
import logging
from typing import Tuple, List, Dict, Any

from PIL import Image
import cv2
import numpy as np

LOGGER = logging.getLogger(__name__)

# Attempt optional OCR import; if unavailable we flag it and degrade gracefully.
_OCR_AVAILABLE = False
pytesseract = None
try:
    import pytesseract as _pytesseract
    pytesseract = _pytesseract
    # Quick check: try calling pytesseract to see if Tesseract binary is accessible.
    pytesseract.get_tesseract_version()
    _OCR_AVAILABLE = True
except Exception as _ocr_err:
    LOGGER.info("pytesseract/Tesseract not available — OCR features disabled: %s", _ocr_err)


# ---------------------------------------------------------------------------
# Image Validation & Loading
# ---------------------------------------------------------------------------

ALLOWED_EXTENSIONS = {".png", ".jpg", ".jpeg", ".webp", ".bmp"}
MAX_IMAGE_BYTES = 10 * 1024 * 1024  # 10 MB


def validate_and_load_image(file_bytes: bytes, filename: str) -> Image.Image:
    """Validate image type and size, then load into a Pillow RGB Image.

    Args:
        file_bytes: Raw uploaded file bytes.
        filename: Original filename for extension check.

    Returns:
        Pillow Image in RGB mode.

    Raises:
        ValueError: If the image is invalid, corrupt, or exceeds size limits.
    """
    if len(file_bytes) > MAX_IMAGE_BYTES:
        raise ValueError("Image exceeds maximum allowed size of 10 MB")

    ext = "." + filename.lower().rsplit(".", 1)[-1] if "." in filename else ""
    if ext not in ALLOWED_EXTENSIONS:
        raise ValueError(f"Unsupported image format: {ext}")

    try:
        img = Image.open(io.BytesIO(file_bytes))
        img.verify()
        # Re-open after verify (verify() invalidates the image object).
        img = Image.open(io.BytesIO(file_bytes)).convert("RGB")
    except Exception as exc:
        raise ValueError(f"Unable to read image: {exc}")

    return img


# ---------------------------------------------------------------------------
# Visual Heuristic Analysis (OpenCV)
# ---------------------------------------------------------------------------

def analyze_visual_structure(pil_img: Image.Image) -> Dict[str, Any]:
    """Detect basic visual components typical of phishing login forms.

    Uses OpenCV contour detection to identify:
      - Input-like rectangular fields (form fields)
      - Button-like rectangular elements
      - Overall layout clutter (high contour count)

    Returns dict with input_fields, buttons, contour_count, visual_points.
    """
    cv_img = cv2.cvtColor(np.array(pil_img), cv2.COLOR_RGB2BGR)
    gray = cv2.cvtColor(cv_img, cv2.COLOR_BGR2GRAY)
    blurred = cv2.GaussianBlur(gray, (5, 5), 0)
    edged = cv2.Canny(blurred, 50, 150)
    # Use RETR_TREE so nested controls inside form bounding boxes are detected
    contours, _ = cv2.findContours(edged, cv2.RETR_TREE, cv2.CHAIN_APPROX_SIMPLE)

    input_like = 0
    button_like = 0
    for cnt in contours:
        x, y, w, h = cv2.boundingRect(cnt)
        area = w * h
        aspect = w / max(h, 1)
        # Input field heuristic: horizontal rectangle with moderate aspect ratio
        if 40 < w < 480 and 15 < h < 90 and 1.5 < aspect < 15 and area > 600:
            input_like += 1
        # Button heuristic: wider than tall, medium-to-large area
        if 60 < w < 350 and 20 < h < 80 and 1.2 < aspect < 8 and area > 1200:
            button_like += 1

    visual_points = 0
    if input_like >= 2:
        visual_points += 15
    elif input_like >= 1:
        visual_points += 8

    if button_like >= 1:
        visual_points += 12

    if len(contours) > 15:
        visual_points += 5

    return {
        "input_fields": input_like,
        "buttons": button_like,
        "contour_count": len(contours),
        "visual_points": min(visual_points, 35),
    }



# ---------------------------------------------------------------------------
# Optional OCR Wrapper
# ---------------------------------------------------------------------------

def extract_ocr_text(pil_img: Image.Image) -> Tuple[str, bool]:
    """Run OCR on the image if pytesseract is available.

    Returns (extracted_text, ocr_available_flag).
    """
    if not _OCR_AVAILABLE:
        return "", False
    try:
        text = pytesseract.image_to_string(pil_img)
        return text, True
    except Exception as exc:
        LOGGER.warning("OCR extraction failed: %s", exc)
        return "", False


# ---------------------------------------------------------------------------
# Text Indicator Detection
# ---------------------------------------------------------------------------

CREDENTIAL_KEYWORDS = {"password", "username", "login", "sign in", "account", "verify", "credentials"}
URGENCY_KEYWORDS = {"immediately", "urgent", "asap", "now", "immediate action", "deadline"}
FINANCIAL_KEYWORDS = {"bank", "credit", "card", "ssn", "social security", "payment", "invoice"}
BRAND_KEYWORDS = {"paypal", "google", "microsoft", "apple", "amazon", "bank of america"}


def extract_text_indicators(text: str) -> Dict[str, List[str]]:
    """Detect keyword-based phishing indicators in OCR text.

    Returns dict mapping categories to lists of matched keywords.
    Only non-empty categories are returned.
    """
    lowered = text.lower()
    matches = {
        "credential": [kw for kw in CREDENTIAL_KEYWORDS if kw in lowered],
        "urgency": [kw for kw in URGENCY_KEYWORDS if kw in lowered],
        "financial": [kw for kw in FINANCIAL_KEYWORDS if kw in lowered],
        "brand": [kw for kw in BRAND_KEYWORDS if kw in lowered],
    }
    return {k: v for k, v in matches.items() if v}


# ---------------------------------------------------------------------------
# URL/Domain Extraction from OCR Text
# ---------------------------------------------------------------------------

URL_REGEX = re.compile(r"https?://[\w\-\.]+(?:\.[a-z]{2,})(?:[/:?#][^\s]*)?", re.IGNORECASE)
DOMAIN_REGEX = re.compile(r"\b(?:(?:[\w\-]+)\.)+[a-z]{2,}\b", re.IGNORECASE)


def extract_domains_and_urls(text: str) -> List[str]:
    """Extract fully-qualified URLs and bare domains from free-form text.

    Returns a deduplicated list of found URLs/domains.
    """
    found = set()
    for match in URL_REGEX.finditer(text):
        found.add(match.group(0))
    for match in DOMAIN_REGEX.finditer(text):
        domain = match.group(0)
        if len(domain) > 4 and "." in domain:
            found.add(domain)
    return list(found)


# ---------------------------------------------------------------------------
# Brand–Domain Correlation
# ---------------------------------------------------------------------------

def correlate_brand_and_domain(brands: List[str], urls: List[str]) -> int:
    """Score mismatch between detected brand keywords and extracted domains.

    Returns 0 if no brands or no URLs, 0 if any brand matches a domain,
    or 20 (mismatch penalty) if brands are found but none appear in the domains.
    """
    if not brands or not urls:
        return 0
    lowered_domains = [u.lower() for u in urls]
    for brand in brands:
        for dom in lowered_domains:
            if brand in dom:
                return 0
    return 20


# ---------------------------------------------------------------------------
# Orchestration Entry Point
# ---------------------------------------------------------------------------

def process_screenshot_analysis(file_bytes: bytes, filename: str) -> Dict[str, Any]:
    """Full pipeline for local screenshot visual analysis.

    Processes the image entirely in-memory, never writes to disk.
    Returns a dict compatible with the unified API response envelope.
    """
    from services.risk_engine import calculate_screenshot_risk
    from services.explanation_builder import build_screenshot_explanation

    # 1. Validate and load image
    pil_img = validate_and_load_image(file_bytes, filename)

    # 2. Visual heuristics
    visual_res = analyze_visual_structure(pil_img)
    visual_points = visual_res.get("visual_points", 0)

    # 3. Optional OCR
    ocr_text, ocr_available = extract_ocr_text(pil_img)
    text_indicators = extract_text_indicators(ocr_text) if ocr_available and ocr_text else {}

    # 4. URL extraction from OCR text
    extracted_urls = extract_domains_and_urls(ocr_text) if ocr_available and ocr_text else []

    # 5. Brand-domain mismatch
    brand_keywords = text_indicators.get("brand", [])
    mismatch_points = correlate_brand_and_domain(brand_keywords, extracted_urls)

    # 6. Compute text indicator points
    text_points = 0
    for cat, words in text_indicators.items():
        text_points += len(words) * 5
    text_points = min(text_points, 25)  # cap here; also capped in risk_engine

    # 7. URL cascade via existing URL Analyzer if any URLs were found
    url_analysis = None
    if extracted_urls:
        try:
            from services.url_analyzer import analyze_url
            # Take the first full URL if available, else the first domain
            full_urls = [u for u in extracted_urls if u.startswith("http")]
            target = full_urls[0] if full_urls else extracted_urls[0]
            url_analysis = analyze_url(target)
        except Exception as exc:
            LOGGER.warning("URL cascade analysis failed safely: %s", exc)
            url_analysis = None

    # 8. Calculate screenshot risk
    total_risk = calculate_screenshot_risk(
        visual_points=visual_points,
        text_points=text_points,
        mismatch_points=mismatch_points,
        url_cascade_points=url_analysis.get("risk_score", 0) if url_analysis and url_analysis.get("success") else 0,
    )

    # 9. Build Phase 9 explanation
    ti_data = url_analysis.get("threat_intelligence") if url_analysis else None
    explanation = build_screenshot_explanation(
        visual_results=visual_res,
        ocr_text=ocr_text if ocr_available else None,
        url_analysis=url_analysis if url_analysis and url_analysis.get("success") else None,
        ti_data=ti_data,
        risk_breakdown=total_risk.get("calculation_breakdown", {}),
    )

    # 10. Assemble response
    prediction = "phishing" if total_risk["risk_score"] >= 55 else (
        "suspicious" if total_risk["risk_score"] >= 25 else "legitimate"
    )

    return {
        "success": True,
        "prediction": prediction,
        "risk_score": total_risk["risk_score"],
        "risk_level": total_risk["risk_level"],
        "recommendation": total_risk["recommendation"],
        "visual_analysis": {
            "input_fields": visual_res["input_fields"],
            "buttons": visual_res["buttons"],
            "contour_count": visual_res["contour_count"],
            "visual_points": visual_res["visual_points"],
            "indicators": text_indicators,
        },
        "ocr_available": ocr_available,
        "ocr_text": ocr_text if ocr_available else None,
        "extracted_urls": extracted_urls,
        "url_analysis": url_analysis if url_analysis and url_analysis.get("success") else None,
        "brand_mismatch_points": mismatch_points,
        "calculation_breakdown": total_risk.get("calculation_breakdown", {}),
        "explanation": explanation,
    }
