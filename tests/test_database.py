"""
test_database.py - Automated Unit & Integration Tests for Phase 6 Database Layer

Covers:
  1. MongoDB offline detection & resilient fallback activation
  2. In-memory storage CRUD & schema compliance
  3. URL scan persistence & canonical field validation
  4. Message scan persistence & model labeling ("Heuristic + URL Cascade")
  5. Privacy sanitization for URLs (userinfo passwords, tokens, API keys)
  6. Privacy sanitization for messages (passwords, OTPs, payment cards)
  7. History retrieval & pagination (limit, offset, total count)
  8. History filtering (scan_type, prediction, risk_level)
  9. Dashboard statistics zero/empty state (no fake data)
  10. Dashboard statistics aggregation (predictions, risk tiers, averages)
  11. Health check endpoint database reporting
  12. Safe query construction & PyMongo injection prevention
  13. Mocked MongoDB online connection & index creation
"""
import sys
import json
from unittest.mock import MagicMock, patch
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))

from config import config
from database.privacy import (
    sanitize_url_for_storage,
    sanitize_message_for_storage,
    sanitize_scan_input
)
from database.mongodb import (
    init_database,
    is_connected,
    save_scan,
    get_scan_history,
    count_scans,
    get_dashboard_statistics,
    reset_in_memory_storage,
    _build_query_filter,
    _filter_memory_records
)
from app import create_app


def test_1_mongodb_offline_detection():
    """Verify that an unavailable MongoDB daemon activates in-memory fallback without crashing."""
    # Connecting to an invalid port guaranteed to be offline
    with patch.object(config, 'MONGODB_URI', 'mongodb://127.0.0.1:54321/'):
        result = init_database()
        assert result is False
        assert is_connected() is False


def test_2_in_memory_fallback_persistence():
    """Verify in-memory fallback stores scans with UUID and ISO timestamp."""
    reset_in_memory_storage()
    dummy_analysis = {
        "prediction": "Legitimate",
        "risk_score": 10,
        "risk_level": "Low",
        "ml_probability_estimate": 0.05,
        "triggered_rules": [],
        "features": {"url_length": 22},
        "recommendation": "Maintain caution."
    }

    scan_id = save_scan("url", "https://example.com", dummy_analysis)
    assert isinstance(scan_id, str)
    assert len(scan_id) == 36  # Standard UUID length

    history = get_scan_history(limit=10)
    assert len(history) == 1
    record = history[0]
    assert record["scan_id"] == scan_id
    assert record["scan_type"] == "url"
    assert record["prediction"] == "Legitimate"
    assert record["risk_score"] == 10
    assert record["risk_level"] == "Low"
    assert "timestamp" in record


def test_3_url_scan_persistence_schema():
    """Verify URL scan document schema contains all canonical Phase 6 fields."""
    reset_in_memory_storage()
    url_analysis = {
        "prediction": "Phishing",
        "risk_score": 88,
        "risk_level": "Critical",
        "ml_probability_estimate": 0.9421,
        "triggered_rules": [{"name": "IP address used as hostname", "score_impact": 22}],
        "features": {"has_ip_address": 1, "url_length": 42},
        "recommendation": "Avoid navigating to this host.",
        "model_loaded": True
    }

    scan_id = save_scan("url", "http://192.168.1.100/login", url_analysis, model_version="1.0.0")
    scans = get_scan_history(limit=1)
    assert len(scans) == 1
    s = scans[0]

    # Verify canonical fields
    assert s["scan_id"] == scan_id
    assert s["scan_type"] == "url"
    assert s["input_type"] == "url"  # backward compat
    assert s["prediction"] == "Phishing"
    assert s["risk_score"] == 88
    assert s["risk_level"] == "Critical"
    assert s["ml_probability"] == 0.9421  # Canonical ML probability
    assert s["model"] == "Random Forest"
    assert "IP address used as hostname" in s["triggered_rules"]
    assert s["features"]["has_ip_address"] == 1
    assert "Avoid navigating" in s["recommendation"]
    assert s["analysis_version"] == "1.0.0"


def test_4_message_scan_persistence_schema():
    """Verify message scan document uses 'Heuristic + URL Cascade' and ml_probability=None."""
    reset_in_memory_storage()
    msg_analysis = {
        "prediction": "Phishing",
        "risk_score": 75,
        "risk_level": "High",
        "detected_indicators": [{"name": "Urgent Time Pressure"}],
        "extracted_urls": ["http://chase-verify.tk"],
        "recommendation": "Social engineering urgency detected."
    }

    save_scan("message", "URGENT: Verify your account immediately", msg_analysis)
    scans = get_scan_history(limit=1)
    assert len(scans) == 1
    s = scans[0]

    assert s["scan_type"] == "message"
    assert s["model"] == "Heuristic + URL Cascade"  # Required Phase 6 label
    assert s["ml_probability"] is None  # Text model not trained yet
    assert "Urgent Time Pressure" in s["triggered_rules"]
    assert s["features"]["extracted_url_count"] == 1


def test_5_privacy_sanitization_url():
    """Verify credentials and sensitive query tokens are scrubbed from stored URLs."""
    raw_url = "http://admin:mySuperSecret123@malicious-site.com/auth?token=eyJhbGciOi&api_key=secretKey999&safe_param=view"
    sanitized = sanitize_url_for_storage(raw_url)

    assert "mySuperSecret123" not in sanitized
    assert "[REDACTED]" in sanitized
    assert "secretKey999" not in sanitized
    assert "safe_param=view" in sanitized
    assert sanitized.startswith("http://admin:[REDACTED]@malicious-site.com")


def test_6_privacy_sanitization_message():
    """Verify passwords, OTPs, and card numbers are scrubbed from stored messages."""
    raw_msg = "Please verify: password: secretPassword456. Your OTP: 123456. Card: 4532 1234 5678 9012"
    sanitized = sanitize_message_for_storage(raw_msg, store_raw=True)

    assert "secretPassword456" not in sanitized
    assert "123456" not in sanitized
    assert "4532 1234 5678 9012" not in sanitized
    assert "[CARD-REDACTED]" in sanitized
    assert "password: [REDACTED]" in sanitized

    # Test STORE_RAW_CONTENT=False
    masked = sanitize_message_for_storage(raw_msg, store_raw=False)
    assert masked == "[Content masked by user privacy setting]"


def test_7_history_retrieval_and_pagination():
    """Verify history limit, offset, and pagination math."""
    reset_in_memory_storage()
    for i in range(25):
        save_scan("url", f"https://example.com/page{i}", {
            "prediction": "Legitimate",
            "risk_score": 5,
            "risk_level": "Low",
            "ml_probability_estimate": 0.02,
            "triggered_rules": []
        })

    # Page 1: 10 records
    page1, total1 = get_scan_history(limit=10, offset=0, return_total=True)
    assert len(page1) == 10
    assert total1 == 25

    # Page 2: 10 records
    page2, total2 = get_scan_history(limit=10, offset=10, return_total=True)
    assert len(page2) == 10
    assert total2 == 25
    assert page1[0]["scan_id"] != page2[0]["scan_id"]

    # Page 3: 5 records
    page3, total3 = get_scan_history(limit=10, offset=20, return_total=True)
    assert len(page3) == 5
    assert total3 == 25


def test_8_history_filtering():
    """Verify filtering by scan_type, prediction, and risk_level."""
    reset_in_memory_storage()
    save_scan("url", "https://phish1.com", {"prediction": "Phishing", "risk_score": 85, "risk_level": "Critical", "triggered_rules": []})
    save_scan("url", "https://legit1.com", {"prediction": "Legitimate", "risk_score": 10, "risk_level": "Low", "triggered_rules": []})
    save_scan("message", "Suspicious message", {"prediction": "Suspicious", "risk_score": 40, "risk_level": "Medium", "detected_indicators": []})

    # Filter by scan_type
    url_scans = get_scan_history(scan_type="url")
    assert len(url_scans) == 2
    assert all(s["scan_type"] == "url" for s in url_scans)

    msg_scans = get_scan_history(scan_type="message")
    assert len(msg_scans) == 1
    assert msg_scans[0]["scan_type"] == "message"

    # Filter by prediction
    phish_scans = get_scan_history(prediction="Phishing")
    assert len(phish_scans) == 1
    assert phish_scans[0]["prediction"] == "Phishing"

    # Filter by risk_level
    crit_scans = get_scan_history(risk_level="Critical")
    assert len(crit_scans) == 1
    assert crit_scans[0]["risk_level"] == "Critical"


def test_9_dashboard_statistics_empty_state():
    """Verify genuine zero state when database has 0 scans (NO fabricated data)."""
    reset_in_memory_storage()
    stats = get_dashboard_statistics()

    assert stats["total_scans"] == 0
    assert stats["predictions"]["phishing"] == 0
    assert stats["predictions"]["legitimate"] == 0
    assert stats["predictions"]["suspicious"] == 0
    assert stats["risk_levels"]["low"] == 0
    assert stats["risk_levels"]["medium"] == 0
    assert stats["risk_levels"]["high"] == 0
    assert stats["risk_levels"]["critical"] == 0
    assert stats["average_risk_score"] == 0.0
    assert stats["top_indicators"] == []


def test_10_dashboard_statistics_calculation():
    """Verify dynamic aggregation across multiple scans."""
    reset_in_memory_storage()
    save_scan("url", "http://bad.com", {
        "prediction": "Phishing",
        "risk_score": 90,
        "risk_level": "Critical",
        "triggered_rules": [{"name": "IP Host"}]
    })
    save_scan("url", "https://good.com", {
        "prediction": "Legitimate",
        "risk_score": 10,
        "risk_level": "Low",
        "triggered_rules": []
    })
    save_scan("message", "Suspicious link alert", {
        "prediction": "Suspicious",
        "risk_score": 50,
        "risk_level": "Medium",
        "detected_indicators": [{"name": "Urgent Time Pressure"}]
    })

    stats = get_dashboard_statistics()
    assert stats["total_scans"] == 3
    assert stats["predictions"]["phishing"] == 1
    assert stats["predictions"]["legitimate"] == 1
    assert stats["predictions"]["suspicious"] == 1
    assert stats["risk_levels"]["critical"] == 1
    assert stats["risk_levels"]["low"] == 1
    assert stats["risk_levels"]["medium"] == 1
    # Average: (90 + 10 + 50) / 3 = 50.0
    assert stats["average_risk_score"] == 50.0
    assert len(stats["top_indicators"]) == 2


def test_11_health_endpoint_reporting():
    """Verify GET /api/health accurately reports in-memory fallback status."""
    app = create_app()
    app.config['TESTING'] = True
    client = app.test_client()

    res = client.get('/api/health')
    assert res.status_code == 200
    data = res.get_json()["data"]

    assert "database" in data
    db_info = data["database"]
    assert "connected" in db_info
    assert "type" in db_info
    if not db_info["connected"]:
        assert db_info["type"] == "in-memory-fallback"
        assert db_info["backend"] == "In-Memory Fallback"


def test_12_safe_query_construction():
    """Verify that PyMongo query construction safely escapes meta-characters."""
    query = _build_query_filter(
        scan_type="url",
        prediction="Phishing",
        risk_level="Critical"
    )
    assert "$or" in query
    assert "prediction" in query
    assert "risk_level" in query

    # Query with special regex characters
    attack_input = "Phishing.*[$]"
    query_attack = _build_query_filter(prediction=attack_input)
    # re.escape must have neutralized wildcards
    pattern = query_attack["prediction"]["$regex"]
    assert r"\.\*" in pattern or r"\[\$\]" in pattern


def test_13_mocked_mongodb_online():
    """Verify that when MongoDB responds to ping, indexes and collections are configured."""
    mock_client = MagicMock()
    mock_db = MagicMock()
    mock_client.__getitem__.return_value = mock_db
    mock_client.admin.command.return_value = {"ok": 1}

    with patch('pymongo.MongoClient', return_value=mock_client):
        result = init_database()
        assert result is True
        assert is_connected() is True
        # Verify indexes were created
        assert mock_db.scans.create_index.call_count >= 4

    # Reset to offline for subsequent in-memory tests
    init_database()

