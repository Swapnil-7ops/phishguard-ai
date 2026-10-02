"""
message_routes.py - Message, QR Code, and Screenshot API Endpoints
"""
import logging
from flask import Blueprint, request, jsonify

from config import config
from services.message_analyzer import analyze_message
from services.qr_service import process_qr_scan
from services.vision_service import analyze_screenshot
from services.screenshot_service import process_screenshot_analysis
from services.email_service import process_email_analysis
from services.llm_service import generate_llm_explanation, is_llm_enabled
from database.mongodb import save_scan

logger = logging.getLogger(__name__)
message_bp = Blueprint('message_bp', __name__)


@message_bp.route('/analyze-message', methods=['POST'])
def handle_analyze_message():
    """
    POST /api/analyze-message
    Payload: { "message": "...", "analyze_urls": true/false, "explain": true/false }
    """
    try:
        data = request.get_json(silent=True) or {}
        raw_msg = data.get("message", "").strip()
        cascade_urls = data.get("analyze_urls", True)
        request_llm = data.get("explain", False)

        if not raw_msg:
            return jsonify({
                "success": False,
                "error": "Message content is required."
            }), 400

        # Execute NLP and link extraction analysis
        result = analyze_message(raw_msg, analyze_extracted_urls=cascade_urls)

        if not result.get("success"):
            return jsonify(result), 400

        # Optional LLM Explanation
        llm_explanation = None
        if request_llm or is_llm_enabled():
            llm_explanation = generate_llm_explanation(result)
        result["llm_explanation"] = llm_explanation

        # Persist scan to database
        scan_id = save_scan(
            input_type="message",
            raw_input=raw_msg,
            analysis_result=result,
            model_version=config.MODEL_VERSION
        )
        result["scan_id"] = scan_id

        return jsonify({
            "success": True,
            "data": result
        }), 200

    except Exception as e:
        logger.error(f"API Error in /analyze-message: {e}", exc_info=True)
        return jsonify({
            "success": False,
            "error": f"Internal server error: {str(e)}"
        }), 500


@message_bp.route('/analyze-qr', methods=['POST'])
def handle_analyze_qr():
    """
    POST /api/analyze-qr
    Accepts multipart/form-data with file key 'image'.
    """
    try:
        if 'image' not in request.files:
            return jsonify({
                "success": False,
                "error": "Image file is required under form field 'image'."
            }), 400

        file = request.files['image']
        if file.filename == '':
            return jsonify({
                "success": False,
                "error": "No file selected."
            }), 400

        filename = file.filename or "qr.png"
        ext = filename.split('.')[-1].lower() if '.' in filename else ''
        if ext not in config.ALLOWED_IMAGE_EXTENSIONS:
            return jsonify({
                "success": False,
                "error": f"Unsupported file type (.{ext}). Allowed: {list(config.ALLOWED_IMAGE_EXTENSIONS)}"
            }), 400

        image_bytes = file.read()
        if len(image_bytes) > config.MAX_CONTENT_LENGTH:
            return jsonify({
                "success": False,
                "error": "Image exceeds the maximum upload limit (10MB)."
            }), 413

        # Process QR Code — image is decoded in memory and discarded
        result = process_qr_scan(image_bytes)

        # Persist if a URL was decoded and analyzed
        if result.get("success") and result.get("payload_type") == "url" and result.get("url_analysis"):
            url_analysis = result["url_analysis"]
            # Persist with scan_type='qr' and raw_input = decoded URL (sanitized by save_scan)
            scan_id = save_scan(
                input_type="qr",
                raw_input=result.get("decoded_url", result.get("decoded_payload", "")),
                analysis_result=url_analysis,
                model_version=config.MODEL_VERSION
            )
            result["scan_id"] = scan_id

        return jsonify({
            "success": True,
            "data": result
        }), 200

    except Exception as e:
        logger.error(f"API Error in /analyze-qr: {e}", exc_info=True)
        return jsonify({
            "success": False,
            "error": f"Internal server error: {str(e)}"
        }), 500


@message_bp.route('/analyze-screenshot', methods=['POST'])
def handle_analyze_screenshot():
    """
    POST /api/analyze-screenshot
    Accepts multipart/form-data with file key 'image'.
    Executes lightweight OpenCV + Pillow visual analysis (Phase 12),
    with optional vision model corroboration if configured.
    """
    try:
        if 'image' not in request.files:
            return jsonify({
                "success": False,
                "error": "Image file is required under form field 'image'."
            }), 400

        file = request.files['image']
        if file.filename == '':
            return jsonify({
                "success": False,
                "error": "No file selected."
            }), 400

        filename = file.filename or "screenshot.png"
        ext = filename.split('.')[-1].lower() if '.' in filename else ''
        if ext not in config.ALLOWED_IMAGE_EXTENSIONS:
            return jsonify({
                "success": False,
                "error": f"Unsupported file type (.{ext}). Allowed: {list(config.ALLOWED_IMAGE_EXTENSIONS)}"
            }), 400

        image_bytes = file.read()
        if len(image_bytes) > config.MAX_CONTENT_LENGTH:
            return jsonify({
                "success": False,
                "error": "Image exceeds maximum upload limit (10MB)."
            }), 413

        # Execute lightweight local visual analysis (Phase 12)
        try:
            result = process_screenshot_analysis(image_bytes, filename)
        except ValueError as val_err:
            return jsonify({
                "success": False,
                "error": str(val_err)
            }), 400
        except Exception as proc_err:
            logger.error(f"Error in process_screenshot_analysis: {proc_err}", exc_info=True)
            return jsonify({
                "success": False,
                "error": f"Visual analysis failed: {str(proc_err)}"
            }), 500

        # Optional supplementary LLM Vision evaluation (if configured)
        vision_supplement = None
        try:
            vision_raw = analyze_screenshot(image_bytes, filename)
            if vision_raw.get("configured") and vision_raw.get("success"):
                vision_supplement = vision_raw.get("data")
        except Exception as v_err:
            logger.debug(f"Optional vision analysis skipped: {v_err}")

        if vision_supplement:
            result["vision_supplement"] = vision_supplement

        # Persist scan to database (metadata only — never store image bytes)
        scan_id = save_scan(
            input_type="screenshot",
            raw_input=f"[Screenshot: {filename}]",
            analysis_result=result,
            model_version=config.MODEL_VERSION
        )
        result["scan_id"] = scan_id

        return jsonify({
            "success": True,
            "data": result
        }), 200

    except Exception as e:
        logger.error(f"API Error in /analyze-screenshot: {e}", exc_info=True)
        return jsonify({
            "success": False,
            "error": f"Internal server error: {str(e)}"
        }), 500


@message_bp.route('/analyze-email', methods=['POST'])
def handle_analyze_email():
    """
    POST /api/analyze-email
    Accepts multipart/form-data with file key 'file'.
    Executes stdlib email parsing and multi-domain forensic analysis (Phase 13).
    """
    try:
        if 'file' not in request.files:
            return jsonify({
                "success": False,
                "error": "Email file is required under form field 'file'."
            }), 400

        file = request.files['file']
        if file.filename == '':
            return jsonify({
                "success": False,
                "error": "No file selected."
            }), 400

        filename = file.filename or "message.eml"
        ext = ("." + filename.lower().rsplit(".", 1)[-1]) if "." in filename else ""
        if ext != '.eml':
            return jsonify({
                "success": False,
                "error": "Unsupported file type. Only .eml files are accepted."
            }), 400

        file_bytes = file.read()
        if len(file_bytes) > config.MAX_CONTENT_LENGTH:
            return jsonify({
                "success": False,
                "error": "Email file exceeds maximum upload limit (10MB)."
            }), 413

        # Process email through in-memory pipeline
        try:
            result = process_email_analysis(file_bytes, filename)
        except ValueError as val_err:
            return jsonify({
                "success": False,
                "error": str(val_err)
            }), 400
        except Exception as proc_err:
            logger.error(f"Error in process_email_analysis: {proc_err}", exc_info=True)
            return jsonify({
                "success": False,
                "error": f"Email analysis failed: {str(proc_err)}"
            }), 500

        # Persist scan to database (metadata only — raw .eml is never saved)
        subject_snippet = result.get("email_analysis", {}).get("headers", {}).get("subject", "")
        scan_id = save_scan(
            input_type="email",
            raw_input=f"[Email: {filename} - {subject_snippet[:80]}]",
            analysis_result=result,
            model_version=config.MODEL_VERSION
        )
        result["scan_id"] = scan_id

        return jsonify({
            "success": True,
            "data": result
        }), 200

    except Exception as e:
        logger.error(f"API Error in /analyze-email: {e}", exc_info=True)
        return jsonify({
            "success": False,
            "error": f"Internal server error: {str(e)}"
        }), 500


