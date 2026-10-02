"""
scan_routes.py - Scan History API Endpoints

WHAT: Exposes historical investigation logs with server-side pagination,
     multi-field filtering, and total count tracking.
WHY: Enables users and security auditors to review past investigations
     and filter by vector type, classification verdict, or risk tier.
"""
import math
import logging
from flask import Blueprint, request, jsonify

from database.mongodb import get_scan_history

logger = logging.getLogger(__name__)
scan_bp = Blueprint('scan_bp', __name__)


@scan_bp.route('/history', methods=['GET'])
def list_history():
    """
    GET /api/history
    Query Parameters:
      - page: int (1-indexed, default: 1)
      - limit: int (default: 20, max: 100)
      - offset: int (optional direct offset, calculated if page is given)
      - type / scan_type: str ('url', 'message', 'all')
      - prediction: str ('Phishing', 'Suspicious', 'Legitimate', 'all')
      - risk_level: str ('Low', 'Medium', 'High', 'Critical', 'all')

    Returns:
      JSON envelope with scans list and pagination metadata.
    """
    try:
        limit = min(100, max(1, int(request.args.get("limit", 20))))

        # If page is explicitly provided, use (page - 1) * limit
        if "page" in request.args:
            page = max(1, int(request.args.get("page", 1)))
            offset = (page - 1) * limit
        else:
            offset = max(0, int(request.args.get("offset", 0)))
            page = (offset // limit) + 1

        scan_type = request.args.get("type") or request.args.get("scan_type")
        prediction = request.args.get("prediction")
        risk_level = request.args.get("risk_level")

        records, total_count = get_scan_history(
            limit=limit,
            offset=offset,
            scan_type=scan_type,
            prediction=prediction,
            risk_level=risk_level,
            return_total=True
        )

        total_pages = max(1, math.ceil(total_count / limit)) if total_count > 0 else 1

        return jsonify({
            "success": True,
            "data": {
                "scans": records,
                "count": len(records),
                "offset": offset,
                "limit": limit,
                "pagination": {
                    "page": page,
                    "limit": limit,
                    "total": total_count,
                    "total_pages": total_pages
                }
            }
        }), 200
    except Exception as e:
        logger.error(f"Error fetching scan history: {e}", exc_info=True)
        return jsonify({
            "success": False,
            "error": f"Failed to retrieve scan history: {str(e)}"
        }), 500
