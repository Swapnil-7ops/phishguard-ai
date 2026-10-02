"""
test_api.py - Integration and Endpoint Tests for Flask REST API
"""
import sys
import json
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))

from app import create_app


def get_test_client():
    app = create_app()
    app.config['TESTING'] = True
    return app.test_client()


def test_health_endpoint():
    """Verify GET /api/health returns 200 and healthy status."""
    client = get_test_client()
    res = client.get('/api/health')
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    assert data["data"]["status"] == "healthy"


def test_dashboard_stats_endpoint():
    """Verify GET /api/dashboard-stats returns 200 with structured counters."""
    client = get_test_client()
    res = client.get('/api/dashboard-stats')
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    assert "total_scans" in data["data"]
    assert "phishing_detected" in data["data"]
    assert "average_risk_score" in data["data"]


def test_model_metrics_endpoint():
    """Verify GET /api/model-metrics returns 200."""
    client = get_test_client()
    res = client.get('/api/model-metrics')
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    assert "url_model" in data["data"]


def test_analyze_url_valid():
    """Verify POST /api/analyze-url with valid URL payload."""
    client = get_test_client()
    payload = {"url": "https://www.google.com"}
    res = client.post('/api/analyze-url', data=json.dumps(payload), content_type='application/json')
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    assert "prediction" in data["data"]
    assert "risk_score" in data["data"]
    assert "reasons" in data["data"]


def test_analyze_url_suspicious_ip():
    """Verify POST /api/analyze-url detects raw IP phishing."""
    client = get_test_client()
    payload = {"url": "http://192.168.1.100/login.php"}
    res = client.post('/api/analyze-url', data=json.dumps(payload), content_type='application/json')
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    assert data["data"]["risk_score"] > 20
    triggered_ids = [r["rule_id"] for r in data["data"]["triggered_rules"]]
    assert "URL_IP" in triggered_ids


def test_analyze_url_empty_validation():
    """Verify POST /api/analyze-url returns 400 on empty input."""
    client = get_test_client()
    payload = {"url": ""}
    res = client.post('/api/analyze-url', data=json.dumps(payload), content_type='application/json')
    assert res.status_code == 400
    data = res.get_json()
    assert data["success"] is False


def test_analyze_message_valid():
    """Verify POST /api/analyze-message extracts URL and scores risk."""
    client = get_test_client()
    payload = {"message": "URGENT: Your bank account is suspended! Log in to verify: http://bank-verify.tk"}
    res = client.post('/api/analyze-message', data=json.dumps(payload), content_type='application/json')
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    assert len(data["data"]["extracted_urls"]) >= 1
    assert data["data"]["risk_score"] > 40


def test_scan_history_endpoint():
    """Verify GET /api/history returns 200 with pagination metadata."""
    client = get_test_client()
    res = client.get('/api/history?page=1&limit=10')
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    assert "scans" in data["data"]
    assert "pagination" in data["data"]
    assert data["data"]["pagination"]["page"] == 1
    assert data["data"]["pagination"]["limit"] == 10


def test_dashboard_stats_breakdown_endpoint():
    """Verify GET /api/dashboard-stats returns structured predictions and risk levels."""
    client = get_test_client()
    res = client.get('/api/dashboard-stats')
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    assert "predictions" in data["data"]
    assert "risk_levels" in data["data"]
    assert "phishing" in data["data"]["predictions"]
    assert "critical" in data["data"]["risk_levels"]
