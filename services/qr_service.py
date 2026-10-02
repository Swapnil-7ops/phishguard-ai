"""
qr_service.py - QR Code Extraction & Quishing Detection Service

WHAT: Decodes uploaded QR code imagery using OpenCV QRCodeDetector,
      extracts embedded payloads, and seamlessly pipelines valid URLs
      into the existing URL Analyzer without fetching the destination.

WHY: QR code phishing ("Quishing") bypasses conventional link filters
     because the destination URL is encoded inside raster pixels rather
     than visible hypertext.

HOW:
  1. Validate and decode image bytes via Pillow (PIL) for format safety.
  2. Decode QR payload via cv2.QRCodeDetector with multi-scale fallback.
  3. Validate decoded payload — URL vs plain text vs dangerous scheme.
  4. Dispatch valid URLs to services.url_analyzer.analyze_url().
  5. Wrap result with QR-specific context metadata.

SECURITY:
  - NEVER makes HTTP requests to the decoded URL.
  - NEVER opens the decoded URL in a browser or subprocess.
  - Reuses existing URL validate_and_normalize_url() for scheme safety.
  - Dangerous schemes (javascript:, data:, file:, vbscript:, about:)
    are detected and rejected before any further processing.

LIMITATIONS:
  - Single-QR-code decoding per image (most reliable path).
  - Heavily compressed, severely blurred, or damaged QR codes may not decode.
  - Requires opencv-python-headless on host system.
"""
import io
import logging
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

# ── Pillow (PIL) ────────────────────────────────────────────────────────────
_PIL_AVAILABLE = False
try:
    from PIL import Image
    _PIL_AVAILABLE = True
except ImportError:
    _PIL_AVAILABLE = False

# ── OpenCV ───────────────────────────────────────────────────────────────────
_CV2_AVAILABLE = False
try:
    import cv2
    import numpy as np
    _CV2_AVAILABLE = True
except ImportError:
    _CV2_AVAILABLE = False

# ── URL Analyzer (Import at module level for testability and reuse) ──────────
from services.url_analyzer import validate_and_normalize_url, analyze_url

# Dangerous schemes that must always be rejected before URL analysis
_DANGEROUS_SCHEMES = frozenset({
    'javascript', 'data', 'file', 'vbscript', 'about',
    'blob', 'chrome', 'chrome-extension', 'resource',
})


def _is_dangerous_scheme(payload: str) -> bool:
    """Return True if the payload starts with a known dangerous scheme."""
    lower = payload.strip().lower()
    for scheme in _DANGEROUS_SCHEMES:
        if lower.startswith(f'{scheme}:'):
            return True
    return False


def _detect_with_fallbacks(detector: Any, bgr: Any) -> Optional[str]:
    """
    Robust multi-strategy QR detection using OpenCV QRCodeDetector:
      1. Original BGR image
      2. Grayscale image
      3. Multiple down/up-scaled variations (handles finder-pattern scaling)
    """
    # 1. Direct BGR
    val, _, _ = detector.detectAndDecode(bgr)
    if val:
        return val.strip()

    # 2. Grayscale
    gray = cv2.cvtColor(bgr, cv2.COLOR_BGR2GRAY)
    val, _, _ = detector.detectAndDecode(gray)
    if val:
        return val.strip()

    # 3. Multi-scale search
    for scale in [0.75, 0.5, 0.6, 1.25]:
        interp = cv2.INTER_AREA if scale < 1.0 else cv2.INTER_LINEAR
        scaled = cv2.resize(bgr, (0, 0), fx=scale, fy=scale, interpolation=interp)
        val, _, _ = detector.detectAndDecode(scaled)
        if val:
            return val.strip()

    return None


def decode_qr_image(image_bytes: bytes) -> Dict[str, Any]:
    """
    Decode QR code payload from raw image bytes.

    Uses OpenCV QRCodeDetector with multi-scale fallback.
    Pillow is used first to validate the image format.

    Args:
        image_bytes: Raw bytes of uploaded image (PNG / JPG / WEBP / BMP / GIF).

    Returns:
        dict with keys:
          success (bool)
          decoded_text (str or None)
          qr_count (int)
          error (str or None)
    """
    if not image_bytes:
        return {
            "success": False,
            "decoded_text": None,
            "qr_count": 0,
            "error": "No image data received.",
        }

    # ── 1. Validate image format via Pillow ──
    if not _PIL_AVAILABLE:
        return {
            "success": False,
            "decoded_text": None,
            "qr_count": 0,
            "error": "Pillow (PIL) library is not installed. Cannot validate image format.",
        }

    try:
        pil_image = Image.open(io.BytesIO(image_bytes))
        pil_image.verify()  # Raises if the image is truncated / corrupt
    except Exception as e:
        return {
            "success": False,
            "decoded_text": None,
            "qr_count": 0,
            "error": f"Invalid or corrupt image file: {str(e)}",
        }

    # Re-open after verify() (verify() closes the file pointer)
    try:
        pil_image = Image.open(io.BytesIO(image_bytes)).convert("RGB")
    except Exception as e:
        return {
            "success": False,
            "decoded_text": None,
            "qr_count": 0,
            "error": f"Image could not be opened for processing: {str(e)}",
        }

    # ── 2. Enforce safe dimension bounds (prevent memory exhaustion) ──
    max_dim = 4096
    w, h = pil_image.size
    if w > max_dim or h > max_dim:
        scale = max_dim / max(w, h)
        pil_image = pil_image.resize((int(w * scale), int(h * scale)), Image.LANCZOS)

    # ── 3. Decode via OpenCV QRCodeDetector ──
    if not _CV2_AVAILABLE:
        return {
            "success": False,
            "decoded_text": None,
            "qr_count": 0,
            "error": (
                "OpenCV (cv2) is not installed on this server environment. "
                "Install with: pip install opencv-python-headless"
            ),
        }

    try:
        img_array = np.array(pil_image)
        bgr = cv2.cvtColor(img_array, cv2.COLOR_RGB2BGR)
        detector = cv2.QRCodeDetector()

        decoded_text = _detect_with_fallbacks(detector, bgr)

        if decoded_text:
            return {
                "success": True,
                "decoded_text": decoded_text,
                "qr_count": 1,
                "error": None,
            }

        return {
            "success": False,
            "decoded_text": None,
            "qr_count": 0,
            "error": (
                "No QR code could be recognized in the uploaded image. "
                "Please ensure the QR code is clear, in focus, and occupies "
                "a reasonable portion of the image."
            ),
        }

    except Exception as e:
        logger.warning(f"OpenCV QR decoding error: {e}")
        return {
            "success": False,
            "decoded_text": None,
            "qr_count": 0,
            "error": f"QR decoding failed due to an unexpected image processing error: {str(e)}",
        }


def _is_url_like(payload: str) -> bool:
    """
    Determine whether payload resembles a URL or plain text before normalization.
    Plain text (e.g. sentences with spaces, arbitrary text without dots)
    must NOT be classified or processed as a URL.
    """
    p = payload.strip()
    if not p:
        return False
    # If the payload contains spaces or newlines before any query/fragment, it's text
    head = p.split('?')[0].split('#')[0]
    if any(c in head for c in (' ', '\n', '\r', '\t')):
        return False

    lower = p.lower()
    if lower.startswith(('http://', 'https://', 'ftp://')):
        return True

    # Scheme-less URL: must have a domain part with at least one dot (e.g. example.com/login)
    domain_part = head.split('/')[0].split(':')[0]
    if '.' in domain_part and len(domain_part) >= 4 and not domain_part.startswith('.') and not domain_part.endswith('.'):
        return True

    return False


def process_qr_scan(image_bytes: bytes) -> Dict[str, Any]:
    """
    Full QR analysis pipeline:
      1. Decode QR image -> get payload.
      2. Classify payload (URL / dangerous scheme / plain text).
      3. If valid URL -> analyze via existing URL analysis pipeline.
      4. Return structured result.

    SECURITY NOTE: NEVER makes HTTP requests to the decoded URL.
    The decoded URL goes through static analysis ONLY.
    """
    decode_result = decode_qr_image(image_bytes)

    if not decode_result.get("success"):
        return {
            "success": False,
            "qr_detected": False,
            "qr_count": decode_result.get("qr_count", 0),
            "payload_type": None,
            "decoded_payload": None,
            "decoded_url": None,
            "url_analysis": None,
            "error": decode_result.get("error", "QR decoding failed."),
        }

    payload: str = decode_result["decoded_text"]

    # ── Check for dangerous schemes FIRST ──
    if _is_dangerous_scheme(payload):
        scheme = payload.split(':')[0].lower()
        return {
            "success": True,
            "qr_detected": True,
            "qr_count": 1,
            "payload_type": "dangerous_scheme",
            "decoded_payload": payload[:100],  # truncate for safety
            "decoded_url": None,
            "url_analysis": None,
            "prediction": "Blocked",
            "risk_score": 100,
            "risk_level": "Critical",
            "recommendation": (
                f"QR code contains a '{scheme}:' payload which is a dangerous scheme "
                "and has been blocked. This QR code must be treated as malicious."
            ),
            "error": None,
        }

    # ── Check if payload is URL-like or plain text ──
    if not _is_url_like(payload):
        return {
            "success": True,
            "qr_detected": True,
            "qr_count": 1,
            "payload_type": "text",
            "decoded_payload": payload,
            "decoded_url": None,
            "url_analysis": None,
            "prediction": "Informational",
            "risk_score": 0,
            "risk_level": "Low",
            "recommendation": (
                "The QR code was decoded successfully. The payload is plain text and "
                "does not appear to be a web URL. No URL risk analysis was performed."
            ),
            "error": None,
        }

    # ── Attempt URL validation using existing analyzer ──
    val = validate_and_normalize_url(payload)

    if val.get("valid"):
        # ── Valid URL -> pass to existing URL analysis pipeline ──
        extracted_url = val["normalized_url"]
        url_analysis = analyze_url(extracted_url)
        # Ensure 'model' key is accessible directly on url_analysis
        if "model" not in url_analysis:
            url_analysis["model"] = url_analysis.get("ml", {}).get("model", "Random Forest")

        return {
            "success": True,
            "qr_detected": True,
            "qr_count": 1,
            "payload_type": "url",
            "decoded_payload": payload,
            "decoded_url": extracted_url,
            "url_analysis": url_analysis,
            # Surface key fields at top level for API convenience
            "prediction": url_analysis.get("prediction", "Unknown"),
            "risk_score": url_analysis.get("risk_score", 0),
            "risk_level": url_analysis.get("risk_level", "Low"),
            "recommendation": url_analysis.get("recommendation", ""),
            "ml_probability": url_analysis.get("ml_probability_estimate"),
            "explanation": url_analysis.get("explanation"),
            "reasons": url_analysis.get("reasons", []),
            "triggered_rules": url_analysis.get("triggered_rules", []),
            "detected_indicators": url_analysis.get("triggered_rules", []),
            "features": url_analysis.get("features", {}),
            "calculation_breakdown": url_analysis.get("calculation_breakdown", {}),
            "threat_intelligence": url_analysis.get("threat_intelligence"),
            "error": None,
        }
    else:
        # ── Payload failed URL normalization ──
        return {
            "success": True,
            "qr_detected": True,
            "qr_count": 1,
            "payload_type": "text",
            "decoded_payload": payload,
            "decoded_url": None,
            "url_analysis": None,
            "prediction": "Informational",
            "risk_score": 0,
            "risk_level": "Low",
            "recommendation": (
                "The QR code was decoded successfully. The payload could not be normalized "
                "as a standard URL. No URL risk analysis was performed."
            ),
            "error": None,
        }
