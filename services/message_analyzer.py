"""
message_analyzer.py - Phishing Email / SMS / Message Analyzer & URL Extractor

WHAT: Analyzes textual messages (emails, SMS, notifications) for social engineering indicators,
     extracts embedded URLs, runs TF-IDF + Logistic Regression classification, and synthesizes
     composite risk through the explainable risk engine.
WHY: Attack vectors often initiate through psychological manipulation in messages directing
     victims to deceptive web resources.
HOW:
  1. Detect regex and linguistic heuristic indicators (urgency, threats, OTP requests, etc.).
  2. Extract all embedded HTTP/HTTPS URLs.
  3. Vectorize text via TF-IDF and infer Malicious/Spam probability via Logistic Regression.
  4. Cascade static URL analysis into extracted links for holistic risk evaluation (Mode A cascade).
  5. Synthesize composite risk score (Text ML 55% + Rules 25% + Cascaded URLs 20%).
  6. Return transparent explainability evidence and actionable security advice.

DATASET & MODEL SEMANTICS:
  Text ML model is trained on the UCI SMS Spam Collection.
  Classification is designated as "SMS Spam/Malicious Message Classifier"
  serving as one evidence source in PhishGuard AI's multi-layered defense.
"""
import re
import json
import logging
from typing import Dict, Any, List, Optional
from pathlib import Path

import joblib

from config import config
from services.risk_engine import calculate_message_risk
from services.explanation_builder import build_message_explanation

logger = logging.getLogger(__name__)

# Heuristic Social Engineering Indicator Rules
NLP_INDICATOR_RULES = [
    {
        "id": "URGENCY",
        "name": "Urgent Time Pressure",
        "severity": "high",
        "severity_score": 10,
        "description": "High urgency phrasing intended to induce panic and force hurried decision making.",
        "pattern": r'\b(urgent|immediately|asap|within 24 hours?|within 2 hours?|right away|act now|hurry|instant action|expires? today|final warning|final notice|limited time)\b'
    },
    {
        "id": "THREAT_SUSPENSION",
        "name": "Account Suspension / Deactivation Threat",
        "severity": "high",
        "severity_score": 10,
        "description": "Threatening language regarding account deactivation, locking, closure, or legal action.",
        "pattern": r'\b(suspend(ed)?|terminat(ed)?|lock(ed)?|block(ed)?|deactivat(ed)?|closed|arrest warrant|legal action|penalty|fine|permanent ban)\b'
    },
    {
        "id": "CREDENTIAL_REQUEST",
        "name": "Credential / Identity Request",
        "severity": "high",
        "severity_score": 10,
        "description": "Direct solicitation of confidential credentials or identity verification.",
        "pattern": r'\b(verify your (identity|account|credentials|password|email)|confirm your (identity|password|details)|update your login|enter your password|provide your pin)\b'
    },
    {
        "id": "OTP_SOLICITATION",
        "name": "One-Time Password (OTP) Interception",
        "severity": "critical",
        "severity_score": 12,
        "description": "Prompts or references to One-Time Passwords (OTP) or 2FA verification tokens.",
        "pattern": r'\b(otp|one[ -]time password|verification code|security code|2fa code|passcode)\b'
    },
    {
        "id": "PAYMENT_DEMAND",
        "name": "Financial / Payment Demand or Fee",
        "severity": "high",
        "severity_score": 8,
        "description": "Unsolicited invoice, transaction fee, delivery fee, or penalty payment demands.",
        "pattern": r'\b(unpaid (fee|invoice|tax)|delivery fee|processing charge|wire transfer|gift card|crypto|bitcoin|refund pending|claim your \$|claim your prize)\b'
    },
    {
        "id": "BRAND_IMPERSONATION",
        "name": "Common Target Brand Impersonation",
        "severity": "medium",
        "severity_score": 7,
        "description": "Explicit references to widely targeted tech, banking, or logistics brands.",
        "pattern": r'\b(paypal|amazon|netflix|apple|microsoft|chase|wells fargo|bank of america|dhl|fedex|usps|irs|social security|coinbase)\b'
    },
    {
        "id": "SUSPICIOUS_CALL_TO_ACTION",
        "name": "Generic Hyperlink Call-To-Action",
        "severity": "medium",
        "severity_score": 6,
        "description": "Vague instructions directing user to click an unverified hyperlink.",
        "pattern": r'\b(click (here|the link|below)|tap (here|the link)|visit (this link|here)|follow the instructions at)\b'
    },
    {
        "id": "EXCESSIVE_CAPITALIZATION",
        "name": "Excessive Capitalization",
        "severity": "low",
        "severity_score": 4,
        "description": "Abuse of all-caps words to simulate authority or acute alarm.",
        "pattern": r'\b[A-Z]{4,}\b'
    }
]

# Model and Vectorizer cache
_TEXT_MODEL_CACHE = None
_VECTORIZER_CACHE = None
_FEATURE_CONFIG_CACHE = None


def load_text_feature_config() -> Optional[Dict[str, Any]]:
    """Load text feature configuration metadata."""
    global _FEATURE_CONFIG_CACHE
    if _FEATURE_CONFIG_CACHE is not None:
        return _FEATURE_CONFIG_CACHE
    cfg_path = getattr(config, 'TEXT_FEATURE_CONFIG_PATH', config.MODELS_DIR / 'text_feature_config.json')
    if cfg_path.exists():
        try:
            with open(cfg_path, 'r', encoding='utf-8') as f:
                _FEATURE_CONFIG_CACHE = json.load(f)
        except Exception as e:
            logger.error(f"Failed to load text feature config: {e}")
    return _FEATURE_CONFIG_CACHE


def load_text_models():
    """Load text classification model and TF-IDF vectorizer."""
    global _TEXT_MODEL_CACHE, _VECTORIZER_CACHE
    if _TEXT_MODEL_CACHE is not None and _VECTORIZER_CACHE is not None:
        return _TEXT_MODEL_CACHE, _VECTORIZER_CACHE

    if not config.TEXT_MODEL_PATH.exists() or not config.TEXT_VECTORIZER_PATH.exists():
        logger.warning("Text model/vectorizer artifacts not found. NLP analysis will rely on heuristic pattern matching.")
        return None, None

    try:
        model = joblib.load(config.TEXT_MODEL_PATH)
        vec = joblib.load(config.TEXT_VECTORIZER_PATH)
        _TEXT_MODEL_CACHE = model
        _VECTORIZER_CACHE = vec
        logger.info("Message NLP Classification Model successfully loaded into memory.")
        return _TEXT_MODEL_CACHE, _VECTORIZER_CACHE
    except Exception as e:
        logger.error(f"Failed to load text classification artifacts: {e}")
        return None, None


def extract_urls(text: str) -> List[str]:
    """
    Find all web URLs embedded inside a text message.
    Supports http, https, and bare domains with paths.
    """
    if not text:
        return []
    url_regex = r'(?:https?:\/\/|www\.)[a-zA-Z0-9.\-_]+(?:\/[a-zA-Z0-9._~:/?#[\]@!$&\'()*+,;=%-]*)?'
    matches = re.findall(url_regex, text, flags=re.IGNORECASE)

    # Normalize URLs starting with www.
    cleaned = []
    for m in matches:
        m = m.rstrip('.,;!?)\'\"')
        if m.lower().startswith('www.'):
            cleaned.append('http://' + m)
        else:
            cleaned.append(m)
    return list(dict.fromkeys(cleaned))  # unique ordered


def extract_indicators(text: str) -> List[Dict[str, Any]]:
    """Scan message text against cybersecurity social engineering heuristics."""
    found = []
    lower_text = text.lower()
    for rule in NLP_INDICATOR_RULES:
        matches = re.findall(rule["pattern"], lower_text if rule["id"] != "EXCESSIVE_CAPITALIZATION" else text, flags=re.IGNORECASE)
        if matches:
            found.append({
                "id": rule["id"],
                "name": rule["name"],
                "severity": rule["severity"],
                "severity_score": rule["severity_score"],
                "description": rule["description"],
                "match_count": len(matches)
            })
    return found


def extract_text_evidence(text: str, clf, vec) -> List[Dict[str, Any]]:
    """
    Extract key vocabulary terms present in the message that contributed
    positively toward the spam/malicious classification log-odds.
    """
    evidence = []
    try:
        X_vec = vec.transform([text])
        feature_names = vec.get_feature_names_out()
        coefs = clf.coef_[0]
        active_indices = X_vec.nonzero()[1]

        for idx in active_indices:
            weight = float(coefs[idx])
            if weight > 0.05:  # Positive weight pushes toward Malicious/Spam
                term = str(feature_names[idx])
                evidence.append({
                    "term": term,
                    "weight": round(weight, 4),
                    "indication": "Spam/Malicious Indicator"
                })
        evidence.sort(key=lambda x: x["weight"], reverse=True)
    except Exception as e:
        logger.debug(f"Could not extract text evidence terms: {e}")
    return evidence[:8]


def analyze_message(text: str, analyze_extracted_urls: bool = True) -> Dict[str, Any]:
    """
    Analyze message text for phishing, extract embedded links, and produce combined intelligence.

    Args:
        text: Raw email, SMS, or notification text.
        analyze_extracted_urls: If True, recursively invoke url_analyzer on discovered links.

    Returns:
        Structured result dict.
    """
    if not text or not isinstance(text, str):
        return {"success": False, "error": "Message content cannot be empty."}

    cleaned_text = text.strip()

    # 1. Linguistic Heuristic Indicators
    indicators = extract_indicators(cleaned_text)

    # 2. Extract URLs
    embedded_urls = extract_urls(cleaned_text)

    # 3. Cascaded URL Analysis (Mode A Pipeline Linkage)
    url_analyses = []
    max_url_risk = 0
    if analyze_extracted_urls and embedded_urls:
        from services.url_analyzer import analyze_url
        for u in embedded_urls[:3]:  # Top 3 embedded URLs
            try:
                res = analyze_url(u)
                if res.get("success"):
                    url_analyses.append(res)
            except Exception as e:
                logger.error(f"Cascaded URL analysis error on {u}: {e}")

    if url_analyses:
        max_url_risk = max((a.get("risk_score", 0) for a in url_analyses), default=0)

    # Extract cascaded threat intelligence if present
    ti_summary = None
    for ua in url_analyses:
        if ua.get("threat_intelligence"):
            ti_summary = ua["threat_intelligence"]
            break

    # 4. Model Inference via TF-IDF + Logistic Regression
    clf, vec = load_text_models()
    feature_cfg = load_text_feature_config()

    if clf is not None and vec is not None:
        try:
            classes = list(clf.classes_)
            # Safely determine malicious class index dynamically
            target_class = feature_cfg.get("target_class", 1) if feature_cfg else 1
            if target_class in classes:
                target_idx = classes.index(target_class)
            else:
                target_idx = 1 if len(classes) > 1 else 0

            X_vec = vec.transform([cleaned_text])
            probs = clf.predict_proba(X_vec)[0]
            text_ml_prob = round(float(probs[target_idx]), 4)
            text_ml_prediction = "Malicious/Spam" if text_ml_prob >= 0.50 else "Legitimate/Ham"
            text_evidence = extract_text_evidence(cleaned_text, clf, vec)
        except Exception as e:
            logger.error(f"Text model inference error: {e}")
            text_ml_prob = 0.50
            text_ml_prediction = "Error"
            text_evidence = []

        # 5. Composite Risk Evaluation (55% Text ML + 25% Rules + 20% URL Cascade)
        risk_info = calculate_message_risk(text_ml_prob, indicators, max_url_risk=max_url_risk)

        final_prediction = "Phishing" if risk_info["risk_score"] >= 55 else ("Suspicious" if risk_info["risk_score"] >= 25 else "Legitimate")

        stored_text = cleaned_text if config.STORE_RAW_CONTENT else "[Content masked for privacy]"

        model_info = {
            "name": "TF-IDF + Logistic Regression",
            "role": "SMS Malicious-Message / Spam Classifier",
            "dataset": "UCI SMS Spam Collection",
            "target_class": "Malicious/Spam (1)"
        }

        # Build structured explanation via adapter (reads existing engine outputs — no re-calculation)
        structured_explanation = build_message_explanation(
            message_preview=stored_text[:140] + ("..." if len(stored_text) > 140 else ""),
            ml_probability=text_ml_prob,
            ml_prediction=text_ml_prediction,
            risk_data=risk_info,
            detected_indicators=indicators,
            url_analyses=url_analyses,
            text_evidence=text_evidence,
        )

        return {
            "success": True,
            "prediction": final_prediction,
            "text_ml_prediction": text_ml_prediction,
            "nlp_prediction": text_ml_prediction,  # backward compatibility alias
            "ml_probability": text_ml_prob,         # canonical field
            "confidence": text_ml_prob,             # backward compatibility alias
            "risk_score": risk_info["risk_score"],
            "risk_level": risk_info["risk_level"],
            "recommendation": risk_info["recommendation"],
            "detected_indicators": indicators,
            "text_evidence": text_evidence,
            "extracted_urls": embedded_urls,
            "url_analyses": url_analyses,
            "threat_intelligence": ti_summary,
            "calculation_breakdown": risk_info["calculation_breakdown"],
            "explanation": structured_explanation,
            "model_info": model_info,
            "message_preview": stored_text[:140] + ("..." if len(stored_text) > 140 else ""),
            "model_loaded": True
        }
    else:
        # Development / Offline mode: Text NLP model not trained or not found
        indicator_weight = sum(ind.get("severity_score", 5) for ind in indicators)
        url_points = min(int(round(max_url_risk * 0.20)), 20) if url_analyses else (15 if embedded_urls else 0)
        rule_score = min(100, indicator_weight + url_points)

        from services.risk_engine import determine_risk_level
        risk_level = determine_risk_level(rule_score)

        stored_text = cleaned_text if config.STORE_RAW_CONTENT else "[Content masked for privacy]"

        return {
            "success": True,
            "prediction": "Suspicious" if rule_score >= 25 else "Legitimate",
            "text_ml_prediction": "Model offline",
            "nlp_prediction": "Model offline",
            "ml_probability": None,
            "confidence": None,
            "risk_score": rule_score,
            "risk_level": risk_level,
            "recommendation": "Linguistic patterns and embedded links extracted. Train the text ML model to generate statistical predictions.",
            "detected_indicators": indicators,
            "text_evidence": [],
            "extracted_urls": embedded_urls,
            "url_analyses": url_analyses,
            "calculation_breakdown": {
                "model_status": "Offline / Training Required",
                "indicator_points": indicator_weight,
                "cascaded_url_risk": max_url_risk,
                "url_points_applied": url_points,
                "formula": f"Indicators ({indicator_weight}) + URL Cascade ({url_points}) = {rule_score}/100"
            },
            "explanation": {
                "text_ml": "Text ML model offline. Analysis relied purely on heuristic patterns.",
                "rules": f"{len(indicators)} social engineering indicator(s) identified.",
                "cascaded_urls": f"{len(url_analyses)} embedded link(s) analyzed." if url_analyses else "No embedded links detected."
            },
            "model_info": {
                "name": "Heuristic Rule Engine (Offline Fallback)",
                "role": "Pattern Matching",
                "dataset": "N/A"
            },
            "threat_intelligence": ti_summary,
            "message_preview": stored_text[:140] + ("..." if len(stored_text) > 140 else ""),
            "model_loaded": False
        }
