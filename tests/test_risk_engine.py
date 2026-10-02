"""
test_risk_engine.py - Automated Unit Tests for the Risk Scoring Engine
"""
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))

from services.risk_engine import (
    calculate_url_risk,
    calculate_message_risk,
    calculate_screenshot_risk,
    calculate_email_risk,
    determine_risk_level
)
import math


def test_score_boundaries():
    """Verify composite risk score never drops below 0 or exceeds 100."""
    # Maximum extreme
    heavy_rules = [{"name": f"Rule {i}", "score_impact": 20, "description": ""} for i in range(10)]
    res_max = calculate_url_risk(1.0, heavy_rules, {})
    assert 0 <= res_max["risk_score"] <= 100
    assert res_max["risk_score"] == 100
    assert res_max["risk_level"] == "Critical"

    # Minimum extreme
    res_min = calculate_url_risk(0.0, [], {})
    assert 0 <= res_min["risk_score"] <= 100
    assert res_min["risk_score"] == 0
    assert res_min["risk_level"] == "Low"


def test_level_thresholds():
    """Verify correct categorization across tier boundaries."""
    assert determine_risk_level(85) == "Critical"
    assert determine_risk_level(80) == "Critical"
    assert determine_risk_level(79) == "High"
    assert determine_risk_level(55) == "High"
    assert determine_risk_level(54) == "Medium"
    assert determine_risk_level(25) == "Medium"
    assert determine_risk_level(24) == "Low"
    assert determine_risk_level(0) == "Low"


def test_tier_boundaries_exhaustive():
    """Verify exact tier boundaries: 0, 1, 24, 25, 54, 55, 79, 80, 99, 100."""
    expected = {
        0: "Low",
        1: "Low",
        24: "Low",
        25: "Medium",
        54: "Medium",
        55: "High",
        79: "High",
        80: "Critical",
        99: "Critical",
        100: "Critical",
    }
    for score, level in expected.items():
        assert determine_risk_level(score) == level, f"Failed at score {score}: expected {level}"


def test_explainability_breakdown_presence():
    """Verify transparency breakdown dictionary contains explicit mathematical formula."""
    rules = [{"name": "Sample Rule", "score_impact": 15, "description": "test"}]
    res = calculate_url_risk(0.85, rules, {})
    bd = res["calculation_breakdown"]
    assert "formula" in bd
    assert "ml_base_points" in bd
    assert "rule_points_applied" in bd
    assert bd["ml_base_points"] == round(0.85 * 60)
    assert bd["rule_points_applied"] == 15


def test_message_risk_scoring():
    """Verify text message risk scoring logic."""
    indicators = [
        {"name": "Urgency", "severity_score": 10},
        {"name": "Threat", "severity_score": 10}
    ]
    res = calculate_message_risk(0.8, indicators)
    assert 0 <= res["risk_score"] <= 100
    assert res["risk_level"] in ("High", "Critical")


def test_url_risk_edge_inputs():
    """Verify defensive handling of None, NaN, inf, and out-of-range probabilities."""
    # None probability defaults safely to 0.0
    res_none = calculate_url_risk(None, [], {})
    assert res_none["risk_score"] == 0
    assert res_none["risk_level"] == "Low"

    # NaN probability defaults safely to 0.0
    res_nan = calculate_url_risk(float("nan"), [], {})
    assert res_nan["risk_score"] == 0

    # +Infinity probability defaults safely to 0.0
    res_inf = calculate_url_risk(float("inf"), [], {})
    assert res_inf["risk_score"] == 0

    # Negative probability clamped to 0.0
    res_neg = calculate_url_risk(-0.75, [], {})
    assert res_neg["risk_score"] == 0

    # Probability > 1.0 clamped to 1.0 (60 ML base points)
    res_over = calculate_url_risk(2.5, [], {})
    assert res_over["risk_score"] == 60


def test_message_risk_edge_inputs():
    """Verify message risk defensive handling of None, NaN, and extreme values."""
    res_none = calculate_message_risk(None, [])
    assert res_none["risk_score"] == 0

    res_nan = calculate_message_risk(float("nan"), [])
    assert res_nan["risk_score"] == 0

    res_inf = calculate_message_risk(float("inf"), [])
    assert res_inf["risk_score"] == 0

    res_over = calculate_message_risk(5.0, [])
    assert res_over["risk_score"] == 55  # 55 max ML points

    # Negative indicator and negative URL risk are non-negative
    res_neg = calculate_message_risk(0.5, [{"severity_score": -10}], max_url_risk=-50)
    assert 0 <= res_neg["risk_score"] <= 100


def test_screenshot_risk_boundaries_and_caps():
    """Verify screenshot risk engine caps and non-negativity."""
    # Zero input
    res_zero = calculate_screenshot_risk(0, 0, 0, 0)
    assert res_zero["risk_score"] == 0
    assert res_zero["risk_level"] == "Low"

    # Max caps individually enforced: visual=35, text=25, mismatch=20, url=20
    res_capped = calculate_screenshot_risk(100, 100, 100, 100)
    assert res_capped["risk_score"] == 100
    bd = res_capped["calculation_breakdown"]
    assert bd["visual_points"] == 35
    assert bd["text_points"] == 25
    assert bd["mismatch_points"] == 20
    assert bd["url_cascade_points"] == 20

    # Negative inputs stay >= 0
    res_neg = calculate_screenshot_risk(-10, -5, -2, -100)
    assert res_neg["risk_score"] == 0


def test_email_risk_boundaries_and_clamping():
    """Verify email risk point caps, non-negativity, and strict [0, 100] clamping."""
    # Zero input
    res_zero = calculate_email_risk(0, 0, 0, 0, 0, 0)
    assert res_zero["risk_score"] == 0
    assert res_zero["risk_level"] == "Low"

    # Max individual caps: 20 + 20 + 15 + 30 + 15 + 20 = 120 points raw, clamped to 100
    res_max = calculate_email_risk(100, 100, 100, 100, 100, 100)
    assert res_max["risk_score"] == 100
    assert res_max["risk_level"] == "Critical"
    bd = res_max["calculation_breakdown"]
    assert bd["header_points"] == 20
    assert bd["auth_points"] == 20
    assert bd["subject_points"] == 15
    assert bd["body_ml_points"] == 30
    assert bd["attachment_points"] == 15
    assert bd["url_cascade_points"] == 20
    assert bd["raw_point_sum"] == 120

    # Negative inputs stay >= 0
    res_neg = calculate_email_risk(-10, -20, -5, -30, -15, -20)
    assert res_neg["risk_score"] == 0


def test_threat_intel_zero_points_guarantee():
    """Verify TI contributes strictly 0 points for all non-successful or 0-detection states."""
    non_scoring_states = [
        None,
        {},
        {"summary": {"status": "not_configured", "detections": 0}},
        {"summary": {"status": "timeout", "detections": 0}},
        {"summary": {"status": "connection_error", "detections": 0}},
        {"summary": {"status": "rate_limited", "detections": 0}},
        {"summary": {"status": "http_error", "detections": 0}},
        {"summary": {"status": "error", "detections": 0}},
        {"summary": {"status": "success", "detections": 0}},  # clean domain
        {"summary": {"status": "success", "detections": -1}}, # invalid detections
    ]
    for ti in non_scoring_states:
        res = calculate_url_risk(0.0, [], {}, threat_intel=ti)
        assert res["risk_score"] == 0, f"TI state {ti} erroneously contributed points!"
        assert res["calculation_breakdown"]["threat_intel_points"] == 0

    # Genuine positive detections:
    # 1 to 4 detections -> +8 points
    res_8 = calculate_url_risk(0.0, [], {}, threat_intel={"summary": {"status": "success", "detections": 3, "total_engines": 70}})
    assert res_8["risk_score"] == 8
    assert res_8["calculation_breakdown"]["threat_intel_points"] == 8

    # 5+ detections -> +15 points
    res_15 = calculate_url_risk(0.0, [], {}, threat_intel={"summary": {"status": "success", "detections": 12, "total_engines": 70}})
    assert res_15["risk_score"] == 15
    assert res_15["calculation_breakdown"]["threat_intel_points"] == 15

