"""
test_text_model.py - Automated Unit Tests for Phase 7 Text ML Model & Pipeline

Tests cover:
  1. Preprocessing accounting integrity (dynamic counts, label mapping {0, 1})
  2. Model artifact persistence & structure
  3. Dynamic class mapping safety (clf.classes_ indexing)
  4. Vectorizer fit isolation (no test data leakage)
  5. High-probability detection on adversarial phrasing
  6. Low-probability scoring on legitimate/benign communication
  7. URL extraction and Mode A cascade integration
  8. Composite risk engine formula boundaries [0, 100] (55/25/20 weights)
  9. Offline fallback resiliency
  10. MongoDB persistence schema (canonical ml_probability)
"""
import sys
import json
from pathlib import Path

import pandas as pd
import joblib

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))

from config import config
from services.message_analyzer import analyze_message, extract_urls, extract_indicators
from services.risk_engine import calculate_message_risk, determine_risk_level
from database.mongodb import save_scan, get_scan_history, reset_in_memory_storage


def test_1_preprocessing_summary_and_dataset():
    """Verify clean dataset exists with valid columns and dynamic non-hardcoded summary."""
    data_path = config.DATA_DIR / 'phishing_messages.csv'
    summary_path = config.DATA_DIR / 'text_preprocessing_summary.json'

    assert data_path.exists(), f"Missing {data_path}"
    assert summary_path.exists(), f"Missing {summary_path}"

    df = pd.read_csv(data_path)
    assert 'text' in df.columns and 'label' in df.columns
    assert len(df) > 1000

    # Ensure binary labels {0, 1}
    unique_labels = set(df['label'].unique())
    assert unique_labels == {0, 1}

    with open(summary_path, 'r', encoding='utf-8') as f:
        summary = json.load(f)

    stats = summary.get("statistics", {})
    assert "raw_rows_ingested" in stats
    assert "valid_parsed_rows" in stats
    assert "dropped_duplicates" in stats
    assert "final_cleaned_rows" in stats
    assert stats["final_cleaned_rows"] == len(df)
    assert stats["dropped_duplicates"] == stats["valid_parsed_rows"] - stats["final_cleaned_rows"]


def test_2_model_artifacts_exist_and_load():
    """Verify all 4 Phase 7 model artifacts exist and load correctly."""
    assert config.TEXT_MODEL_PATH.exists()
    assert config.TEXT_VECTORIZER_PATH.exists()
    assert config.TEXT_FEATURE_CONFIG_PATH.exists()
    assert config.TEXT_MODEL_METRICS_PATH.exists()

    clf = joblib.load(config.TEXT_MODEL_PATH)
    vec = joblib.load(config.TEXT_VECTORIZER_PATH)
    assert hasattr(clf, "predict_proba")
    assert hasattr(vec, "transform")


def test_3_dynamic_class_mapping_safety():
    """Verify class indexing dynamically inspects classes_ to avoid assuming index 1."""
    clf = joblib.load(config.TEXT_MODEL_PATH)
    classes = list(clf.classes_)
    assert 1 in classes
    assert 0 in classes

    with open(config.TEXT_FEATURE_CONFIG_PATH, 'r', encoding='utf-8') as f:
        cfg = json.load(f)

    target_idx = classes.index(cfg.get("target_class", 1))
    assert target_idx >= 0
    assert target_idx == cfg.get("class_index_in_predict_proba")


def test_4_data_leakage_absence():
    """Verify vectorizer transform does not alter vocabulary or leak test distribution."""
    vec = joblib.load(config.TEXT_VECTORIZER_PATH)
    initial_vocab_len = len(vec.vocabulary_)

    test_unseen = ["Unseen novel test phrase with unique terminology 987654"]
    X_unseen = vec.transform(test_unseen)

    assert len(vec.vocabulary_) == initial_vocab_len
    assert X_unseen.shape[1] == initial_vocab_len


def test_5_inference_known_phishing_message():
    """Verify model infers high probability on urgent smishing attack."""
    msg = "URGENT: Your Chase checking account has been locked. Verify immediately at http://chase-update.tk to avoid penalty."
    res = analyze_message(msg, analyze_extracted_urls=False)

    assert res["success"] is True
    assert res["model_loaded"] is True
    assert res["ml_probability"] is not None
    assert res["ml_probability"] >= 0.50
    assert res["text_ml_prediction"] == "Malicious/Spam"
    assert res["risk_score"] >= 50
    assert len(res["text_evidence"]) > 0


def test_6_inference_known_legitimate_message():
    """Verify model infers low probability on benign conversational message."""
    msg = "Hey Swapnil, let me know what time works best for tomorrow's project meeting."
    res = analyze_message(msg, analyze_extracted_urls=False)

    assert res["success"] is True
    assert res["model_loaded"] is True
    assert res["ml_probability"] is not None
    assert res["ml_probability"] < 0.35
    assert res["text_ml_prediction"] == "Legitimate/Ham"
    assert res["risk_level"] in ("Low", "Medium")


def test_7_url_extraction_and_cascading():
    """Verify message analyzer extracts embedded URLs and performs Mode A analysis cascade."""
    msg = "Please review our update: http://legit-site.com and confirm at https://secure-auth.org/login"
    urls = extract_urls(msg)

    assert len(urls) == 2
    assert "http://legit-site.com" in urls
    assert "https://secure-auth.org/login" in urls

    res = analyze_message(msg, analyze_extracted_urls=True)
    assert res["success"] is True
    assert len(res["extracted_urls"]) == 2
    assert "url_analyses" in res


def test_8_composite_risk_engine_formula_and_bounds():
    """Verify composite message risk calculation arithmetic (55/25/20 weights)."""
    # Max extreme
    high_indicators = [{"name": f"Ind {i}", "severity_score": 10} for i in range(5)]
    res_max = calculate_message_risk(text_probability=1.0, indicators_detected=high_indicators, max_url_risk=100)

    assert res_max["risk_score"] == 100
    assert res_max["risk_level"] == "Critical"
    bd = res_max["calculation_breakdown"]
    assert bd["text_ml_points"] == 55
    assert bd["indicator_points_applied"] == 25
    assert bd["url_points_applied"] == 20

    # Min extreme
    res_min = calculate_message_risk(text_probability=0.0, indicators_detected=[], max_url_risk=0)
    assert res_min["risk_score"] == 0
    assert res_min["risk_level"] == "Low"

    # Intermediate test
    res_mid = calculate_message_risk(text_probability=0.50, indicators_detected=[{"name": "Urgency", "severity_score": 10}], max_url_risk=50)
    assert 0 <= res_mid["risk_score"] <= 100
    assert res_mid["calculation_breakdown"]["text_ml_points"] == round(0.50 * 55)
    assert res_mid["calculation_breakdown"]["indicator_points_applied"] == 10
    assert res_mid["calculation_breakdown"]["url_points_applied"] == min(round(50 * 0.20), 20)


def test_9_offline_fallback_safety():
    """Verify analyze_message handles missing models gracefully without raising unhandled exceptions."""
    import services.message_analyzer as ma
    orig = ma.load_text_models
    try:
        ma.load_text_models = lambda: (None, None)
        res = ma.analyze_message("Urgent notice with no model loaded", analyze_extracted_urls=False)
        assert res["success"] is True
        assert res["model_loaded"] is False
        assert res["ml_probability"] is None
        assert "Offline" in res["calculation_breakdown"]["model_status"]
    finally:
        ma.load_text_models = orig


def test_10_database_persistence_schema():
    """Verify message scan is persisted to storage with canonical ml_probability and Phase 7 model tag."""
    reset_in_memory_storage()

    analysis = {
        "prediction": "Phishing",
        "text_ml_prediction": "Malicious/Spam",
        "ml_probability": 0.8842,
        "confidence": 0.8842,
        "risk_score": 82,
        "risk_level": "Critical",
        "detected_indicators": [{"name": "Urgent Time Pressure"}],
        "extracted_urls": ["http://chase-update.tk"],
        "recommendation": "Do not enter credentials.",
        "model_loaded": True
    }

    scan_id = save_scan("message", "URGENT: Verify account now", analysis)
    scans = get_scan_history(limit=1)
    assert len(scans) == 1
    s = scans[0]

    assert s["scan_id"] == scan_id
    assert s["scan_type"] == "message"
    assert s["ml_probability"] == 0.8842
    assert "TF-IDF + Logistic Regression" in s["model"]
    assert s["risk_score"] == 82
    assert s["risk_level"] == "Critical"
