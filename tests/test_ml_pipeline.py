"""
test_ml_pipeline.py - Automated Unit & Integration Tests for Phase 3 ML Pipeline

Covers:
  1. Dataset preprocessing integrity
  2. 25-feature output
  3. Training matrix shape verification
  4. Label mapping correctness (0=Legitimate, 1=Phishing)
  5. Model loading
  6. Model prediction
  7. Probability / class mapping safety
  8. Metrics generation & structure
  9. Random Forest feature importance
  10. URL analyzer with trained model end-to-end
"""
import sys
import json
import joblib
from pathlib import Path
import pandas as pd
import numpy as np

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))

from config import config
from ml.feature_extractor import extract_url_features, get_feature_names
from services.url_analyzer import load_model, analyze_url


def test_1_dataset_preprocessing():
    """Verify data/datasets/phishing_urls.csv exists, is clean, and has correct schema."""
    csv_path = config.DATA_DIR / 'phishing_urls.csv'
    assert csv_path.exists(), f"Missing cleaned dataset at {csv_path}"

    df = pd.read_csv(csv_path, nrows=1000)
    assert 'url' in df.columns, "Dataset missing 'url' column"
    assert 'label' in df.columns, "Dataset missing 'label' column"
    assert df['label'].isin([0, 1]).all(), "Labels must be binary 0 or 1"
    assert df['url'].isnull().sum() == 0, "No null URLs allowed"


def test_2_feature_count_and_names():
    """Verify feature extractor produces exactly the canonical 25 features."""
    names = get_feature_names()
    assert len(names) == 25, f"Expected 25 features, got {len(names)}"

    feats = extract_url_features("https://www.google.com")
    assert len(feats) == 25
    assert set(feats.keys()) == set(names)


def test_3_training_matrix_shape():
    """Verify feature matrix on multiple URLs has shape (N, 25)."""
    sample_urls = [
        "https://www.google.com",
        "http://192.168.1.1/login.php",
        "https://github.com/torvalds/linux",
        "http://security-paypal.com@attacker.xyz/update"
    ]
    fnames = get_feature_names()
    matrix = [[extract_url_features(u).get(fn, 0) for fn in fnames] for u in sample_urls]
    df = pd.DataFrame(matrix, columns=fnames)

    assert df.shape[1] == 25
    assert df.shape[0] == len(sample_urls)
    assert not df.isnull().any().any()


def test_4_label_mapping_integrity():
    """Verify feature_config.json specifies 0=Legitimate and 1=Phishing."""
    assert config.FEATURE_CONFIG_PATH.exists()
    with open(config.FEATURE_CONFIG_PATH, 'r', encoding='utf-8') as f:
        cfg = json.load(f)

    assert cfg.get("feature_count") == 25
    assert "label_mapping" in cfg
    lm = cfg["label_mapping"]
    assert lm.get("phishing_class") == 1
    assert lm.get("legitimate_class") == 0
    assert lm.get("normalized_to_name", {}).get("0") == "Legitimate"
    assert lm.get("normalized_to_name", {}).get("1") == "Phishing"


def test_5_model_file_exists_and_loads():
    """Verify trained primary Random Forest model loads from models/url_model.pkl."""
    assert config.URL_MODEL_PATH.exists(), f"Model file missing at {config.URL_MODEL_PATH}"
    model = joblib.load(config.URL_MODEL_PATH)
    assert hasattr(model, "predict"), "Loaded object lacks predict method"
    assert hasattr(model, "predict_proba"), "Loaded object lacks predict_proba method"
    assert hasattr(model, "classes_"), "Loaded model lacks classes_ attribute"
    assert set(model.classes_).issubset({0, 1})


def test_6_model_prediction():
    """Verify model predict and predict_proba outputs are valid."""
    model = joblib.load(config.URL_MODEL_PATH)
    fnames = get_feature_names()

    # Synthetic test sample
    sample = [0] * len(fnames)
    pred = model.predict([sample])[0]
    assert pred in (0, 1)

    proba = model.predict_proba([sample])[0]
    assert len(proba) == 2
    assert 0.0 <= proba[0] <= 1.0
    assert 0.0 <= proba[1] <= 1.0
    assert abs(sum(proba) - 1.0) < 0.01


def test_7_probability_class_mapping():
    """Verify that phishing probability correctly maps to class 1 without reversal."""
    model = joblib.load(config.URL_MODEL_PATH)
    fnames = get_feature_names()
    with open(config.FEATURE_CONFIG_PATH, 'r', encoding='utf-8') as f:
        cfg = json.load(f)

    phish_class = cfg["label_mapping"]["phishing_class"]
    classes = list(model.classes_)
    phish_idx = classes.index(phish_class)

    # Obvious phishing URL with multiple red flags (IP, @ symbol, disposable TLD)
    phish_feats = extract_url_features("http://192.168.1.100@paypal-verify.tk/login.php?user=admin")
    phish_vec = [phish_feats.get(fn, 0) for fn in fnames]
    phish_probs = model.predict_proba([phish_vec])[0]
    phishing_probability = phish_probs[phish_idx]

    # Obvious legitimate URL
    legit_feats = extract_url_features("https://www.google.com")
    legit_vec = [legit_feats.get(fn, 0) for fn in fnames]
    legit_probs = model.predict_proba([legit_vec])[0]
    legitimate_probability = legit_probs[phish_idx]

    assert phishing_probability > legitimate_probability
    assert legitimate_probability < 0.20
    assert phishing_probability > 0.80


def test_8_metrics_file_structure():
    """Verify models/model_metrics.json has all required fields."""
    assert config.MODEL_METRICS_PATH.exists(), f"Missing metrics file at {config.MODEL_METRICS_PATH}"
    with open(config.MODEL_METRICS_PATH, 'r', encoding='utf-8') as f:
        metrics = json.load(f)

    assert "dataset" in metrics
    assert "features" in metrics
    assert "models" in metrics
    assert "comparison" in metrics
    assert "primary_model" in metrics
    assert "feature_importance" in metrics

    # Verify all 3 models are evaluated
    models_dict = metrics["models"]
    for m in ["Logistic Regression", "Decision Tree", "Random Forest"]:
        assert m in models_dict, f"Missing evaluation for {m}"
        m_eval = models_dict[m]
        assert 0.80 <= m_eval["accuracy"] <= 1.0
        assert 0.80 <= m_eval["precision"] <= 1.0
        assert 0.80 <= m_eval["recall"] <= 1.0
        assert 0.80 <= m_eval["f1_score"] <= 1.0
        cm = m_eval["confusion_matrix"]
        for key in ["true_negative", "false_positive", "false_negative", "true_positive"]:
            assert key in cm
            assert isinstance(cm[key], int)


def test_9_feature_importance_validity():
    """Verify feature importances are extracted, non-negative, and sum to ~1.0."""
    with open(config.MODEL_METRICS_PATH, 'r', encoding='utf-8') as f:
        metrics = json.load(f)

    fi_list = metrics["feature_importance"]
    assert len(fi_list) == 25, "Feature importance must include all 25 features"

    total_imp = sum(item["importance"] for item in fi_list)
    assert abs(total_imp - 1.0) < 0.05
    for item in fi_list:
        assert item["importance"] >= 0.0
        assert item["feature"] in get_feature_names()


def test_10_url_analyzer_with_trained_model():
    """Verify services.url_analyzer loads model and produces valid predictions and risk scores."""
    res_legit = analyze_url("https://www.google.com")
    assert res_legit["success"] is True
    assert res_legit["model_loaded"] is True
    assert res_legit["prediction"] == "Legitimate"
    assert res_legit["ml_prediction"] == "Legitimate"
    assert 0 <= res_legit["risk_score"] <= 100
    assert 0.0 <= res_legit["ml_probability_estimate"] <= 1.0
    assert res_legit["risk_level"] in ("Low", "Medium", "High", "Critical")

    res_phish = analyze_url("http://192.168.1.100/secure/login.php?user=admin")
    assert res_phish["success"] is True
    assert res_phish["model_loaded"] is True
    assert res_phish["prediction"] == "Phishing"
    assert res_phish["ml_prediction"] == "Phishing"
    assert res_phish["risk_score"] >= 55
    assert res_phish["ml_probability_estimate"] >= 0.50
