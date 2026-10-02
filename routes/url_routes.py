"""
url_routes.py - URL Analysis & Model Metrics API Endpoints
"""
import json
import logging
from flask import Blueprint, request, jsonify

from config import config
from services.url_analyzer import analyze_url
from services.llm_service import generate_llm_explanation, is_llm_enabled
from database.mongodb import save_scan

logger = logging.getLogger(__name__)
url_bp = Blueprint('url_bp', __name__)


@url_bp.route('/analyze-url', methods=['POST'])
def handle_analyze_url():
    """
    POST /api/analyze-url
    Payload: { "url": "https://...", "explain": true/false }
    """
    try:
        data = request.get_json(silent=True) or {}
        raw_url = data.get("url", "").strip()
        request_llm = data.get("explain", False)

        if not raw_url:
            return jsonify({
                "success": False,
                "error": "URL parameter is required and cannot be empty."
            }), 400

        # Execute analysis
        result = analyze_url(raw_url)

        if not result.get("success"):
            return jsonify(result), 400

        # Optional LLM Explanation
        llm_explanation = None
        if request_llm or is_llm_enabled():
            llm_explanation = generate_llm_explanation(result)
        result["llm_explanation"] = llm_explanation

        # Persist scan to database
        scan_id = save_scan(
            input_type="url",
            raw_input=raw_url,
            analysis_result=result,
            model_version=config.MODEL_VERSION
        )
        result["scan_id"] = scan_id

        return jsonify({
            "success": True,
            "data": result
        }), 200

    except Exception as e:
        logger.error(f"API Error in /analyze-url: {e}", exc_info=True)
        return jsonify({
            "success": False,
            "error": f"Internal server error: {str(e)}"
        }), 500


@url_bp.route('/model-metrics', methods=['GET'])
def get_model_metrics():
    """
    GET /api/model-metrics
    Returns performance metrics from the actual trained models (offline evaluation).
    """
    metrics = {
        "url_model": None,
        "text_model": None
    }

    if config.MODEL_METRICS_PATH.exists():
        try:
            with open(config.MODEL_METRICS_PATH, 'r', encoding='utf-8') as f:
                raw = json.load(f)
                primary = raw.get("primary_evaluation", {})
                dataset_info = raw.get("dataset", {})
                metrics["url_model"] = {
                    "dataset_name": f"{dataset_info.get('name', 'PhiUSIIL')} ({dataset_info.get('source', 'UCI')})",
                    "total_samples": f"{dataset_info.get('total_cleaned_samples', 0):,}",
                    "train_samples": f"{dataset_info.get('train_samples', 0):,}",
                    "test_samples": f"{dataset_info.get('test_samples', 0):,}",
                    "accuracy": primary.get("accuracy", 0),
                    "precision": primary.get("precision", 0),
                    "recall": primary.get("recall", 0),
                    "f1_score": primary.get("f1_score", 0),
                    "confusion_matrix": primary.get("confusion_matrix", {}),
                    "feature_importance": raw.get("feature_importance", []),
                    "comparison": raw.get("comparison", []),
                    "models": raw.get("models", {}),
                    "primary_model": raw.get("primary_model", "Random Forest")
                }
        except Exception as e:
            logger.error(f"Could not read URL model_metrics file: {e}")
    elif config.EVAL_RESULTS_PATH.exists():
        try:
            with open(config.EVAL_RESULTS_PATH, 'r', encoding='utf-8') as f:
                metrics["url_model"] = json.load(f)
        except Exception as e:
            logger.error(f"Could not read URL eval file: {e}")

    text_metrics_path = getattr(config, 'TEXT_MODEL_METRICS_PATH', config.TEXT_EVAL_PATH)
    if not text_metrics_path.exists() and config.TEXT_EVAL_PATH.exists():
        text_metrics_path = config.TEXT_EVAL_PATH

    if text_metrics_path.exists():
        try:
            with open(text_metrics_path, 'r', encoding='utf-8') as f:
                metrics["text_model"] = json.load(f)
        except Exception as e:
            logger.error(f"Could not read text eval file: {e}")

    return jsonify({
        "success": True,
        "data": metrics
    }), 200
