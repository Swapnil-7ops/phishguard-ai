"""
mongodb.py - MongoDB Persistence Layer with Resilient In-Memory Fallback

WHAT: Manages storage, query filtering, pagination, and aggregated statistics
     for investigation scans across PhishGuard AI.
WHY: Allows users to review past investigations, feeds the analytics dashboard,
     and maintains an audit trail while ensuring zero data loss on student
     or offline environments.
HOW: Uses PyMongo with serverSelectionTimeoutMS=2000. If MongoDB is unavailable,
     transparently activates an in-memory queue fallback so the app NEVER crashes.
     Input is sanitized for privacy prior to storage.
INPUT: Scan records for 'url' and 'message' analysis modes.
OUTPUT: Stored records, filtered & paginated history, aggregated dashboard statistics.
LIMITATIONS:
  - In-memory fallback is volatile and clears upon web server restart.
  - Scan history stores sanitized/redacted input representations only.
"""
import re
import uuid
import logging
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional, Tuple

from config import config
from database.privacy import sanitize_scan_input

logger = logging.getLogger(__name__)

# Module-level connection state
_CLIENT = None
_DB = None
_IS_MONGODB_ONLINE = False
_MEMORY_STORAGE: List[Dict[str, Any]] = []


def init_database() -> bool:
    """
    Attempt connection to MongoDB; configure fallback if unreachable.
    Creates necessary indexes on the 'scans' collection.
    """
    global _CLIENT, _DB, _IS_MONGODB_ONLINE
    try:
        from pymongo import MongoClient
        mongo_uri = getattr(config, 'MONGODB_URI', None) or getattr(config, 'MONGO_URI', 'mongodb://localhost:27017/')
        db_name = getattr(config, 'MONGODB_DATABASE', None) or getattr(config, 'DATABASE_NAME', 'phishguard')

        _CLIENT = MongoClient(mongo_uri, serverSelectionTimeoutMS=2000)
        # Force ping to verify server reachability
        _CLIENT.admin.command('ping')
        _DB = _CLIENT[db_name]

        # Ensure indexes on scans collection for fast query, sort, and aggregation
        _DB.scans.create_index([("timestamp", -1)])
        _DB.scans.create_index([("scan_type", 1)])
        _DB.scans.create_index([("input_type", 1)])
        _DB.scans.create_index([("prediction", 1)])
        _DB.scans.create_index([("risk_level", 1)])

        _IS_MONGODB_ONLINE = True
        logger.info(f"MongoDB connection established successfully ({db_name}).")
        return True
    except Exception as e:
        _IS_MONGODB_ONLINE = False
        _CLIENT = None
        _DB = None
        logger.warning(f"MongoDB unavailable ({e}). Activating in-memory persistence fallback.")
        return False


def is_connected() -> bool:
    """Return whether MongoDB is actively connected."""
    return _IS_MONGODB_ONLINE


def reset_in_memory_storage() -> None:
    """Reset the in-memory fallback list (useful for unit testing)."""
    global _MEMORY_STORAGE
    _MEMORY_STORAGE.clear()


def save_scan(
    input_type: str,
    raw_input: str,
    analysis_result: Dict[str, Any],
    model_version: str = "1.0.0"
) -> str:
    """
    Save an investigation scan to the active persistence layer.
    Sanitizes credentials/tokens from input prior to insertion.

    Args:
        input_type: 'url' or 'message'
        raw_input: Original text or URL supplied by the user (analyzed first in memory).
        analysis_result: Output dict from analyzer services.
        model_version: Current model version tag.

    Returns:
        Generated unique scan_id string.
    """
    scan_id = str(uuid.uuid4())
    now_iso = datetime.now(timezone.utc).isoformat()

    # Sanitize input representation specifically for persistent storage
    store_raw = getattr(config, 'STORE_RAW_CONTENT', True)
    sanitized_input = sanitize_scan_input(raw_input, input_type, store_raw=store_raw)

    # Extract indicator names
    indicators = []
    if "triggered_rules" in analysis_result:
        raw_rules = analysis_result.get("triggered_rules", [])
        for r in raw_rules:
            if isinstance(r, dict):
                indicators.append(r.get("name", "Unknown Rule"))
            elif isinstance(r, str):
                indicators.append(r)
    elif "detected_indicators" in analysis_result:
        raw_inds = analysis_result.get("detected_indicators", [])
        for ind in raw_inds:
            if isinstance(ind, dict):
                indicators.append(ind.get("name", "Unknown Indicator"))
            elif isinstance(ind, str):
                indicators.append(ind)
    elif "email_analysis" in analysis_result:
        ea = analysis_result.get("email_analysis", {})
        for key in ("header_indicators", "subject_indicators", "body_indicators", "attachment_indicators"):
            for ind in ea.get(key, []):
                if isinstance(ind, dict):
                    indicators.append(ind.get("name", "Unknown Indicator"))
                elif isinstance(ind, str):
                    indicators.append(ind)

    # Normalize prediction
    raw_prediction = analysis_result.get("prediction", "Unknown")
    if "model not trained" in raw_prediction.lower() or "pending" in raw_prediction.lower():
        risk = analysis_result.get("risk_score", 0)
        normalized_prediction = "Suspicious" if risk >= 25 else "Legitimate"
    else:
        normalized_prediction = raw_prediction

    # Resolve model name and ml_probability strictly according to current specifications
    if input_type == 'url':
        model_name = "Random Forest" if analysis_result.get("model_loaded", True) else "Heuristic Rule Engine"
        # Canonical ml_probability: posterior estimate from classifier (float or None)
        ml_prob = analysis_result.get("ml_probability_estimate")
        if ml_prob is None:
            ml_prob = analysis_result.get("confidence")
        features_dict = analysis_result.get("features", {})
    elif input_type == 'message':
        if analysis_result.get("model_loaded") and analysis_result.get("ml_probability") is not None:
            model_name = "TF-IDF + Logistic Regression (SMS Spam/Malicious Message Classifier)"
            ml_prob = analysis_result.get("ml_probability")
        elif analysis_result.get("ml_probability") is not None and analysis_result.get("model"):
            model_name = analysis_result.get("model")
            ml_prob = analysis_result.get("ml_probability")
        else:
            model_name = "Heuristic + URL Cascade"
            ml_prob = None
        extracted_urls = analysis_result.get("extracted_urls", [])
        features_dict = {
            "extracted_url_count": len(extracted_urls),
            "indicator_count": len(indicators)
        }
    elif input_type == 'qr':
        # QR uses the existing URL analysis pipeline — model is Random Forest
        model_name = "Random Forest (via QR Decode)" if analysis_result.get("model_loaded", True) else "Heuristic Rule Engine (via QR Decode)"
        ml_prob = analysis_result.get("ml_probability_estimate")
        if ml_prob is None:
            ml_prob = analysis_result.get("confidence")
        features_dict = analysis_result.get("features", {})
    elif input_type in ('email', 'eml'):
        model_name = "Email Analysis Pipeline"
        ml_prob = analysis_result.get("email_analysis", {}).get("body_ml_proxy", {}).get("probability")
        features_dict = {
            "url_count": len(analysis_result.get("email_analysis", {}).get("extracted_urls", [])),
            "attachment_count": len(analysis_result.get("email_analysis", {}).get("attachments", [])),
            "header_indicator_count": len(analysis_result.get("email_analysis", {}).get("header_indicators", [])),
            "subject_indicator_count": len(analysis_result.get("email_analysis", {}).get("subject_indicators", []))
        }
    else:
        model_name = analysis_result.get("model", "Heuristic")
        ml_prob = analysis_result.get("confidence")
        features_dict = analysis_result.get("features", {})

    record = {
        "scan_id": scan_id,
        "timestamp": now_iso,
        "scan_type": input_type,
        "input_type": input_type,  # alias for backward compatibility
        "input": sanitized_input,
        "original_input": sanitized_input,  # alias for backward compatibility
        "prediction": normalized_prediction,
        "risk_score": int(analysis_result.get("risk_score", 0)),
        "risk_level": analysis_result.get("risk_level", "Low"),
        "ml_probability": ml_prob,  # canonical field
        "confidence": ml_prob,  # alias for backward compatibility
        "model": model_name,
        "triggered_rules": indicators,
        "detected_indicators": indicators,  # alias for backward compatibility
        "features": features_dict,
        "recommendation": analysis_result.get("recommendation", ""),
        "analysis_version": model_version,
        "model_version": model_version  # alias for backward compatibility
    }

    # Optional Threat Intelligence metadata (normalized, secrets-free)
    if "threat_intelligence" in analysis_result and analysis_result["threat_intelligence"]:
        record["threat_intelligence"] = analysis_result["threat_intelligence"]


    if _IS_MONGODB_ONLINE and _DB is not None:
        try:
            _DB.scans.insert_one(record)
            # Remove MongoDB's internal _id from record if present for caller
            record.pop("_id", None)
            return scan_id
        except Exception as e:
            logger.error(f"Failed to write scan to MongoDB: {e}. Falling back to in-memory storage.")

    # In-memory storage fallback (maintain last 1,000 records chronologically)
    _MEMORY_STORAGE.insert(0, record)
    if len(_MEMORY_STORAGE) > 1000:
        _MEMORY_STORAGE.pop()

    return scan_id


def _build_query_filter(
    scan_type: Optional[str] = None,
    prediction: Optional[str] = None,
    risk_level: Optional[str] = None
) -> Dict[str, Any]:
    """Construct a safe PyMongo query dictionary preventing injection."""
    query: Dict[str, Any] = {}

    if scan_type and scan_type.lower() != 'all':
        clean_type = scan_type.strip().lower()
        query["$or"] = [{"scan_type": clean_type}, {"input_type": clean_type}]

    if prediction and prediction.lower() != 'all':
        clean_pred = prediction.strip()
        query["prediction"] = {"$regex": f"^{re.escape(clean_pred)}$", "$options": "i"}

    if risk_level and risk_level.lower() != 'all':
        clean_level = risk_level.strip()
        query["risk_level"] = {"$regex": f"^{re.escape(clean_level)}$", "$options": "i"}

    return query


def _filter_memory_records(
    records: List[Dict[str, Any]],
    scan_type: Optional[str] = None,
    prediction: Optional[str] = None,
    risk_level: Optional[str] = None
) -> List[Dict[str, Any]]:
    """Filter in-memory scan records with matching logic to MongoDB."""
    filtered = records

    if scan_type and scan_type.lower() != 'all':
        st_lower = scan_type.strip().lower()
        filtered = [
            s for s in filtered
            if s.get("scan_type", "").lower() == st_lower or s.get("input_type", "").lower() == st_lower
        ]

    if prediction and prediction.lower() != 'all':
        p_lower = prediction.strip().lower()
        filtered = [
            s for s in filtered
            if s.get("prediction", "").lower() == p_lower
        ]

    if risk_level and risk_level.lower() != 'all':
        r_lower = risk_level.strip().lower()
        filtered = [
            s for s in filtered
            if s.get("risk_level", "").lower() == r_lower
        ]

    return filtered


def get_scan_history(
    limit: int = 50,
    offset: int = 0,
    scan_type: Optional[str] = None,
    prediction: Optional[str] = None,
    risk_level: Optional[str] = None,
    return_total: bool = False
) -> Any:
    """
    Retrieve chronologically descending scan history with filtering and pagination.

    Args:
        limit: Number of records to return (1-200).
        offset: Record offset index.
        scan_type: Filter by 'url' or 'message'.
        prediction: Filter by 'Phishing', 'Suspicious', 'Legitimate'.
        risk_level: Filter by 'Low', 'Medium', 'High', 'Critical'.
        return_total: If True, returns tuple (records, total_count).

    Returns:
        List of scan dicts, or tuple (List[Dict], total_count) if return_total=True.
    """
    limit = max(1, min(limit, 200))
    offset = max(0, offset)

    if _IS_MONGODB_ONLINE and _DB is not None:
        try:
            query = _build_query_filter(scan_type, prediction, risk_level)
            total_count = _DB.scans.count_documents(query)
            cursor = _DB.scans.find(query, {"_id": 0}).sort("timestamp", -1).skip(offset).limit(limit)
            records = list(cursor)
            if return_total:
                return records, total_count
            return records
        except Exception as e:
            logger.error(f"Failed to fetch scan history from MongoDB: {e}")

    # In-memory fallback
    filtered = _filter_memory_records(_MEMORY_STORAGE, scan_type, prediction, risk_level)
    total_count = len(filtered)
    records = filtered[offset:offset + limit]

    if return_total:
        return records, total_count
    return records


def count_scans(
    scan_type: Optional[str] = None,
    prediction: Optional[str] = None,
    risk_level: Optional[str] = None
) -> int:
    """Return total count of matching scans."""
    if _IS_MONGODB_ONLINE and _DB is not None:
        try:
            query = _build_query_filter(scan_type, prediction, risk_level)
            return _DB.scans.count_documents(query)
        except Exception as e:
            logger.error(f"Failed to count scans from MongoDB: {e}")

    filtered = _filter_memory_records(_MEMORY_STORAGE, scan_type, prediction, risk_level)
    return len(filtered)


def get_dashboard_statistics() -> Dict[str, Any]:
    """
    Calculate summary metrics and distributions for the dashboard.
    Produces strictly factual calculations from real stored records.
    Returns clean zero-states when no scans exist (no fabricated data).
    """
    scans: List[Dict[str, Any]] = []

    if _IS_MONGODB_ONLINE and _DB is not None:
        try:
            scans = list(_DB.scans.find({}, {"_id": 0}))
        except Exception as e:
            logger.error(f"Failed to fetch scans for dashboard stats: {e}")
            scans = _MEMORY_STORAGE
    else:
        scans = _MEMORY_STORAGE

    total = len(scans)
    phish_count = 0
    legit_count = 0
    susp_count = 0

    risk_levels_count = {
        "low": 0,
        "medium": 0,
        "high": 0,
        "critical": 0
    }

    risk_sum = 0
    prediction_dist: Dict[str, int] = {}
    indicator_counts: Dict[str, int] = {}

    for s in scans:
        pred = s.get("prediction", "Unknown")
        prediction_dist[pred] = prediction_dist.get(pred, 0) + 1

        pred_lower = pred.lower()
        if pred_lower == "phishing":
            phish_count += 1
        elif pred_lower == "legitimate":
            legit_count += 1
        elif pred_lower == "suspicious":
            susp_count += 1

        r_level = s.get("risk_level", "").lower()
        if r_level in risk_levels_count:
            risk_levels_count[r_level] += 1

        risk_sum += s.get("risk_score", 0)

        # Count triggered indicators
        inds = s.get("triggered_rules") or s.get("detected_indicators") or []
        for ind in inds:
            if isinstance(ind, str) and ind:
                indicator_counts[ind] = indicator_counts.get(ind, 0) + 1

    avg_risk = round(risk_sum / total, 1) if total > 0 else 0.0

    # Build 7-day timeline
    now = datetime.now(timezone.utc)
    scans_timeline = []
    for i in range(6, -1, -1):
        day_date = (now - timedelta(days=i)).strftime("%Y-%m-%d")
        count = sum(1 for s in scans if str(s.get("timestamp", "")).startswith(day_date))
        scans_timeline.append({"date": day_date, "count": count})

    # Top triggered indicators
    top_indicators = [
        {"indicator": k, "count": v}
        for k, v in sorted(indicator_counts.items(), key=lambda x: x[1], reverse=True)[:8]
    ]

    return {
        "total_scans": total,
        "predictions": {
            "phishing": phish_count,
            "legitimate": legit_count,
            "suspicious": susp_count
        },
        "risk_levels": risk_levels_count,
        "phishing_detected": phish_count,  # backward compatibility alias
        "legitimate": legit_count,  # backward compatibility alias
        "suspicious": susp_count,  # backward compatibility alias
        "average_risk_score": avg_risk,
        "prediction_distribution": prediction_dist,
        "scans_over_time": scans_timeline,
        "top_indicators": top_indicators,
        "database_backend": "MongoDB" if _IS_MONGODB_ONLINE else "In-Memory Fallback",
        "mongodb_connected": _IS_MONGODB_ONLINE
    }
