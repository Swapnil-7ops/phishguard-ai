"""
url_analyzer.py - Complete URL Analysis Orchestrator

WHAT: Coordinates URL validation, feature extraction, ML inference, rule evaluation,
     and composite risk scoring.
WHY: Encapsulates the entire Mode A analysis lifecycle in a modular, testable interface.
HOW:
  1. Validate URL syntax and format (refuse SSRF attacks or malformed strings).
  2. Normalize URL (standardize scheme, hostname casing, punycode).
  3. Extract 25 deterministic features via ml.feature_extractor.
  4. Perform RandomForest probability prediction.
  5. Evaluate deterministic security indicators via services.rule_engine.
  6. Calculate composite Risk Score and Risk Level via services.risk_engine.
  7. Assemble structured, explainable response dictionary.
INPUT: URL string (str).
OUTPUT: Comprehensive structured dictionary.
LIMITATIONS:
  - Static lexical analysis cannot evaluate server runtime response or dynamic payload delivery.
  - Does not open socket connections to destination hosts.
"""
import re
import json
import logging
from urllib.parse import urlparse, urlunparse
from typing import Dict, Any, Optional

import pandas as pd
import joblib

from config import config
from ml.feature_extractor import extract_url_features, get_feature_names
from services.rule_engine import evaluate_rules
from services.risk_engine import calculate_url_risk
from services.explanation_builder import build_url_explanation
from services.threat_intelligence import get_threat_intel_service

logger = logging.getLogger(__name__)

# Cache for model and feature configuration
_MODEL_CACHE: Optional[Any] = None
_FEATURE_NAMES_CACHE: Optional[list] = None
_LABEL_CONFIG_CACHE: Optional[dict] = None


def load_model():
    """Load and cache the trained RandomForest model, feature ordering, and label mapping."""
    global _MODEL_CACHE, _FEATURE_NAMES_CACHE, _LABEL_CONFIG_CACHE
    if _MODEL_CACHE is not None and _FEATURE_NAMES_CACHE is not None:
        return _MODEL_CACHE, _FEATURE_NAMES_CACHE, _LABEL_CONFIG_CACHE

    if not config.URL_MODEL_PATH.exists():
        logger.warning(f"URL model artifact not found at {config.URL_MODEL_PATH}. Prediction will run in heuristic mode.")
        return None, None, None

    try:
        model = joblib.load(config.URL_MODEL_PATH)
        feature_names = get_feature_names()
        label_config = {"phishing_class": 1, "legitimate_class": 0}

        if config.FEATURE_CONFIG_PATH.exists():
            with open(config.FEATURE_CONFIG_PATH, 'r', encoding='utf-8') as f:
                f_cfg = json.load(f)
                feature_names = f_cfg.get("feature_names", feature_names)
                label_config = f_cfg.get("label_mapping", label_config)

        _MODEL_CACHE = model
        _FEATURE_NAMES_CACHE = feature_names
        _LABEL_CONFIG_CACHE = label_config
        logger.info("URL Machine Learning Model successfully loaded into memory.")
        return _MODEL_CACHE, _FEATURE_NAMES_CACHE, _LABEL_CONFIG_CACHE
    except Exception as e:
        logger.error(f"Error loading URL model: {e}")
        return None, None, None


def validate_and_normalize_url(raw_url: str) -> Dict[str, Any]:
    """
    Validate and normalize user-provided URL input.

    Returns:
        Dict containing 'valid' (bool), 'normalized_url' (str), and optional 'error' (str).
    """
    if not raw_url or not isinstance(raw_url, str):
        return {"valid": False, "error": "URL input cannot be empty."}

    url_str = raw_url.strip()
    if len(url_str) > 2048:
        return {"valid": False, "error": "URL length exceeds standard maximum boundary (2048 characters)."}

    # Basic safety filter: reject dangerous non-web schemes
    disallowed_schemes = ('javascript:', 'data:', 'file:', 'vbscript:', 'about:')
    if any(url_str.lower().startswith(s) for s in disallowed_schemes):
        return {"valid": False, "error": "Unsupported or unsafe protocol scheme."}

    # Ensure valid scheme prefix
    if not re.match(r'^[a-zA-Z][a-zA-Z0-9+-.]*://', url_str):
        url_str = 'http://' + url_str

    try:
        parsed = urlparse(url_str)
        if not parsed.netloc:
            return {"valid": False, "error": "Malformed URL: missing hostname or domain."}

        # Normalize host to lowercase
        netloc = parsed.netloc.lower()
        path = parsed.path
        if path == '/':
            path = ''
        normalized = urlunparse((
            parsed.scheme.lower(),
            netloc,
            path,
            parsed.params,
            parsed.query,
            parsed.fragment
        ))
        return {"valid": True, "normalized_url": normalized}
    except Exception as e:
        return {"valid": False, "error": f"URL parsing error: {str(e)}"}


def analyze_url(url: str) -> Dict[str, Any]:
    """
    Execute the full end-to-end URL analysis pipeline.

    Args:
        url: User-provided URL string.

    Returns:
        Structured analysis results dictionary.
    """
    # 1. Validation and Normalization
    val_res = validate_and_normalize_url(url)
    if not val_res["valid"]:
        return {
            "success": False,
            "error": val_res.get("error", "Invalid URL"),
            "input_url": url
        }

    norm_url = val_res["normalized_url"]

    # 2. Feature Extraction
    features = extract_url_features(norm_url)

    # 3. Model Inference & Rule Evaluation
    model, feature_names, label_config = load_model()
    triggered_rules = evaluate_rules(features)

    if model is not None and feature_names is not None:
        try:
            feature_vector = [features.get(f, 0) for f in feature_names]
            X_df = pd.DataFrame([feature_vector], columns=feature_names)
            probs = model.predict_proba(X_df)[0]

            # Dynamically identify the probability corresponding to the phishing class (never assume index 1)
            phishing_class_target = label_config.get("phishing_class", 1) if label_config else 1
            model_classes = list(getattr(model, "classes_", [0, 1]))

            if phishing_class_target in model_classes:
                phish_idx = model_classes.index(phishing_class_target)
            else:
                phish_idx = 1 if len(model_classes) > 1 else 0

            phishing_prob = float(probs[phish_idx])
            ml_probability_estimate = round(phishing_prob, 4)
            ml_confidence = ml_probability_estimate  # Maintained for UI/API consistency
            ml_prediction = "Phishing" if phishing_prob >= 0.50 else "Legitimate"
        except Exception as e:
            logger.error(f"Inference error: {e}")
            ml_prediction = "Error"
            ml_confidence = 0.5
            ml_probability_estimate = 0.5

        # ── Threat Intelligence Lookup (Optional External Corroboration) ──
        ti_result = None
        try:
            ti_service = get_threat_intel_service()
            ti_result = ti_service.lookup_url(norm_url)
        except Exception as e:
            logger.warning(f"Threat Intelligence lookup failed safely: {e}")
            ti_result = {
                "enabled": False,
                "queried": False,
                "providers": [],
                "summary": {
                    "status": "error",
                    "malicious": False,
                    "suspicious": False,
                    "detections": 0,
                    "total_engines": 0,
                    "risk_points": 0,
                    "description": f"Threat intelligence query failed safely: {str(e)}"
                }
            }

        risk_data = calculate_url_risk(
            ml_confidence,
            triggered_rules,
            features,
            threat_intel=ti_result
        )

        if risk_data["risk_score"] >= 55:
            overall_prediction = "Phishing"
        elif risk_data["risk_score"] >= 25:
            overall_prediction = "Suspicious"
        else:
            overall_prediction = "Legitimate"

        # Build structured explanation via adapter (reads existing engine outputs — no re-calculation)
        explanation_dict = build_url_explanation(
            url=norm_url,
            features=features,
            ml_probability=ml_probability_estimate,
            ml_prediction=ml_prediction,
            risk_data=risk_data,
            triggered_rules=triggered_rules,
            model=model,
            feature_names=feature_names,
            threat_intel=ti_result,
        )

        return {
            "success": True,
            "input_url": url,
            "normalized_url": norm_url,
            "prediction": overall_prediction,
            "ml_prediction": ml_prediction,
            "ml_probability_estimate": ml_probability_estimate,
            "confidence": ml_confidence,
            "risk_score": risk_data["risk_score"],
            "risk_level": risk_data["risk_level"],
            "reasons": risk_data["reasons"],
            "recommendation": risk_data["recommendation"],
            "triggered_rules": triggered_rules,
            "calculation_breakdown": risk_data["calculation_breakdown"],
            "features": features,
            "ml": {
                "available": True,
                "model": "Random Forest",
                "phishing_probability": ml_probability_estimate
            },
            "rules": {
                "triggered": triggered_rules,
                "total_points": risk_data["calculation_breakdown"].get("rule_points_applied", 0)
            },
            "threat_intelligence": ti_result,
            "explanation": explanation_dict,
            "model_loaded": True
        }
    else:
        # Development mode: ML model not trained yet (DO NOT fabricate prediction)
        ti_result = None
        try:
            ti_service = get_threat_intel_service()
            ti_result = ti_service.lookup_url(norm_url)
        except Exception as e:
            logger.warning(f"Threat Intelligence lookup failed safely: {e}")
            ti_result = {
                "enabled": False,
                "queried": False,
                "providers": [],
                "summary": {"status": "error", "risk_points": 0}
            }

        rule_impact_sum = sum(r.get("score_impact", 0) for r in triggered_rules)
        rule_score = min(rule_impact_sum, 40)
        risk_level = "High" if rule_score >= 30 else ("Medium" if rule_score >= 15 else "Low")
        reasons = [f"{r['name']} (+{r['score_impact']} pts): {r['description']}" for r in triggered_rules]
        if not reasons:
            reasons = ["No heuristic security rule anomalies triggered on this URL structure."]

        return {
            "success": True,
            "input_url": url,
            "normalized_url": norm_url,
            "prediction": "ML model not trained yet — feature analysis available",
            "ml_prediction": "Model training pending",
            "confidence": None,
            "risk_score": rule_score,
            "risk_level": risk_level,
            "reasons": reasons,
            "recommendation": "Feature and rule indicators extracted. Train the Random Forest classifier to obtain full probabilistic predictions.",
            "triggered_rules": triggered_rules,
            "calculation_breakdown": {
                "model_status": "Training Pending",
                "rule_points_applied": rule_score,
                "formula": f"Rule Heuristic Score = {rule_score}/40 (Full ML composite scoring pending model training)"
            },
            "features": features,
            "threat_intelligence": ti_result,
            "model_loaded": False
        }

