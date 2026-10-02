"""
dashboard_routes.py - Analytics Dashboard & Health Check Endpoints
"""
import logging
from flask import Blueprint, jsonify

from config import config
from database.mongodb import get_dashboard_statistics, is_connected
from services.llm_service import is_llm_enabled
from services.vision_service import is_vision_enabled

logger = logging.getLogger(__name__)
dashboard_bp = Blueprint('dashboard_bp', __name__)


@dashboard_bp.route('/dashboard-stats', methods=['GET'])
def get_stats():
    """
    GET /api/dashboard-stats
    Provides aggregated metrics for Chart.js and summary cards.
    Calculates dynamic counts and distributions without fabricated numbers.
    """
    try:
        stats = get_dashboard_statistics()
        return jsonify({
            "success": True,
            "data": stats
        }), 200
    except Exception as e:
        logger.error(f"Error fetching dashboard statistics: {e}", exc_info=True)
        return jsonify({
            "success": False,
            "error": f"Failed to compute dashboard metrics: {str(e)}"
        }), 500


@dashboard_bp.route('/health', methods=['GET'])
def health_check():
    """
    GET /api/health
    Operational diagnostic endpoint reporting service and database status.
    Clearly distinguishes whether MongoDB is connected or running in in-memory fallback.
    """
    from services.url_analyzer import load_model
    from services.message_analyzer import load_text_models

    url_m, _, _ = load_model()
    text_m, _ = load_text_models()
    
    connected = is_connected()
    db_type = "mongodb" if connected else "in-memory-fallback"
    db_backend = "MongoDB" if connected else "In-Memory Fallback"

    status = {
        "status": "healthy",
        "service": "PhishGuard AI Backend",
        "version": config.MODEL_VERSION,
        "database": {
            "connected": connected,
            "type": db_type,
            "backend": db_backend
        },
        "models": {
            "url_model_loaded": url_m is not None,
            "text_model_loaded": text_m is not None
        },
        "services": {
            "llm_explanation_enabled": is_llm_enabled(),
            "vision_screenshot_enabled": is_vision_enabled()
        }
    }
    return jsonify({
        "success": True,
        "data": status
    }), 200
