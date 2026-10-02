"""
explanation_builder.py - Structured Explanation Adapter for PhishGuard AI

WHAT: Assembles a clean, evidence-based explanation dictionary by consuming
      the EXISTING outputs of url_analyzer, message_analyzer, rule_engine,
      risk_engine, and feature_extractor — without modifying any of those modules.
WHY:  Provides a structured investigation report that is traceable to actual
      computed evidence (ML probability, rule triggers, extracted features,
      risk engine contributions).
HOW:
  - Adapts existing triggered_rules list (already contains rule_id, name,
    severity, score_impact, description) into a structured rule_evidence list.
  - Uses ml/feature_descriptions.py to convert raw feature values into
    human-readable observations.
  - Reads risk contribution breakdown directly from the risk engine output.
  - Optionally exposes Random Forest global feature_importances_ (labeled
    accurately as GLOBAL MODEL FEATURE IMPORTANCE — not per-sample attribution).

IMPORTANT:
  - Never recalculates risk scores; uses the values returned by risk_engine.
  - Never claims "this feature caused the model to classify as phishing".
  - HTTPS is described as encrypted transport only — NOT as a safety guarantee.
  - Global feature_importances_ is labeled as global, not per-sample.
  - All evidence is drawn from actual backend data only.
"""

import logging
from typing import Dict, Any, List, Optional

from ml.feature_descriptions import describe_all_features

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _what_does_this_mean(risk_level: str) -> str:
    """Return a probabilistic, evidence-based summary for the given risk level."""
    levels = {
        "Low": (
            "No major suspicious structural indicators were detected. "
            "The analyzed resource exhibits characteristics consistent with legitimate web resources. "
            "Maintain standard security awareness and never provide credentials if prompted unexpectedly."
        ),
        "Medium": (
            "Some suspicious structural characteristics were detected. "
            "Multiple risk signals contributed to an elevated risk score. "
            "Verify the sender or destination through an independent channel before taking action."
        ),
        "High": (
            "Multiple suspicious indicators were detected across ML inference and deterministic rules. "
            "Avoid entering passwords, personal information, or sensitive data until legitimacy is independently verified."
        ),
        "Critical": (
            "Strong converging indicators of malicious or credential-harvesting activity were detected. "
            "Avoid interacting with this resource. Do not enter any credentials or personal information. "
            "Report this through the appropriate security channel."
        ),
    }
    return levels.get(risk_level, "No assessment available.")


# ---------------------------------------------------------------------------
# URL Explanation Builder
# ---------------------------------------------------------------------------

def build_url_explanation(
    url: str,
    features: Dict[str, Any],
    ml_probability: float,
    ml_prediction: str,
    risk_data: Dict[str, Any],
    triggered_rules: List[Dict[str, Any]],
    model: Optional[Any] = None,
    feature_names: Optional[List[str]] = None,
    threat_intel: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Build the full structured explanation for a URL analysis result.

    Args:
        url: The normalized URL string that was analyzed.
        features: The 25-feature dict from feature_extractor.
        ml_probability: Phishing probability from the Random Forest (0.0–1.0).
        ml_prediction: Human-readable class label ("Phishing" / "Legitimate").
        risk_data: The dict returned by calculate_url_risk() — used as-is.
        triggered_rules: The list of triggered rule dicts from evaluate_rules().
        model: The loaded RandomForestClassifier (optional — for global importance).
        feature_names: Ordered list of feature names matching the model (optional).
        threat_intel: Optional Threat Intelligence dictionary from ThreatIntelService.

    Returns:
        Explanation dict with keys:
            summary, ml_evidence, rule_evidence, feature_evidence,
            risk_contribution, what_does_this_mean, recommendation,
            global_feature_importance (optional), investigation_stages,
            threat_intelligence
    """
    bd = risk_data.get("calculation_breakdown", {})
    risk_score = risk_data.get("risk_score", 0)
    risk_level = risk_data.get("risk_level", "Low")

    # ── 1. Summary ─────────────────────────────────────────────────────────
    rule_count = len(triggered_rules)
    ti_summary_text = ""
    if threat_intel and threat_intel.get("summary", {}).get("detections", 0) > 0:
        d = threat_intel["summary"]["detections"]
        t = threat_intel["summary"]["total_engines"]
        ti_summary_text = f" External threat intelligence flagged {d}/{t} malicious engine detections."

    summary = (
        f"Analysis of the submitted URL produced a Risk Score of {risk_score}/100 "
        f"({risk_level} Risk). "
        f"The Random Forest model assigned a phishing probability of "
        f"{ml_probability * 100:.1f}%. "
        f"{rule_count} deterministic security rule indicator(s) were triggered."
        f"{ti_summary_text}"
    )

    # ── 2. ML Evidence ─────────────────────────────────────────────────────
    ml_points = bd.get("ml_base_points", int(round(ml_probability * 60)))
    ml_max = bd.get("ml_max_possible", 60)
    ml_evidence = {
        "model": "Random Forest Classifier",
        "phishing_probability": round(ml_probability, 4),
        "phishing_probability_pct": round(ml_probability * 100, 1),
        "predicted_class": ml_prediction,
        "points_contributed": ml_points,
        "points_maximum": ml_max,
        "interpretation": (
            f"The trained Random Forest model estimated a {ml_probability * 100:.1f}% "
            f"probability of phishing based on the 25 extracted lexical and structural features. "
            f"Elevated malicious probability was produced by the trained model."
            if ml_probability >= 0.50 else
            f"The trained Random Forest model estimated a {ml_probability * 100:.1f}% "
            f"probability of phishing ({(1 - ml_probability) * 100:.1f}% consistent with "
            f"legitimate domain patterns)."
        ),
    }

    # ── 3. Rule Evidence (adapter over existing triggered_rules output) ────
    rule_evidence = []
    for r in triggered_rules:
        rule_evidence.append({
            "rule_id": r.get("rule_id", ""),
            "rule": r.get("name", ""),
            "description": r.get("description", ""),
            "severity": r.get("severity", ""),
            "contribution": r.get("score_impact", 0),
        })

    rule_points = bd.get("rule_points_applied", min(
        sum(r.get("score_impact", 0) for r in triggered_rules), 40
    ))
    rule_max = bd.get("rule_max_possible", 40)

    # ── 4. Feature Evidence ────────────────────────────────────────────────
    all_feature_evidence = describe_all_features(features)
    # Noteworthy / suspicious features bubble to top of the investigation
    noteworthy_first = sorted(
        all_feature_evidence,
        key=lambda x: {"suspicious": 0, "noteworthy": 1, "normal": 2}.get(x["level"], 2)
    )

    # ── 5. Risk Contribution ───────────────────────────────────────────────
    ti_pts = bd.get("threat_intel_points", 0)
    formula_str = bd.get("formula")
    if not formula_str:
        if ti_pts > 0:
            formula_str = f"Final Risk Score = min(100, ML_Base({ml_points}) + Rule_Impact({rule_points}) + Threat_Intel({ti_pts})) = {risk_score}/100"
        else:
            formula_str = f"Final Risk Score = min(100, ML_Base({ml_points}) + Rule_Impact({rule_points})) = {risk_score}/100"

    risk_contribution = {
        "ml_points": ml_points,
        "ml_points_maximum": ml_max,
        "rule_points": rule_points,
        "rule_points_maximum": rule_max,
        "threat_intel_points": ti_pts,
        "total_score": risk_score,
        "total_maximum": 100,
        "formula": formula_str,
    }

    # ── 6. Investigation Timeline (URL scan) ──────────────────────────────
    ti_stage_detail = "Threat Intelligence disabled or not configured."
    if threat_intel and threat_intel.get("enabled"):
        ti_sum = threat_intel.get("summary", {})
        st = ti_sum.get("status")
        if st == "success":
            dets = ti_sum.get("detections", 0)
            tot = ti_sum.get("total_engines", 0)
            ti_stage_detail = f"VirusTotal queried — {dets}/{tot} security engines reported malicious activity."
        elif st == "rate_limited":
            ti_stage_detail = "VirusTotal lookup rate-limited; analysis preserved via local ML and rules."
        elif st == "timeout":
            ti_stage_detail = "VirusTotal lookup timed out; fallback to local ML and rules."
        elif st == "not_found":
            ti_stage_detail = "VirusTotal queried — URL not previously cataloged."
        else:
            ti_stage_detail = f"VirusTotal lookup status: {st}."

    investigation_stages = [
        {"stage": "Input", "detail": "URL submitted for analysis."},
        {"stage": "URL Validation & Normalization", "detail": f"URL validated and normalized: {url}"},
        {"stage": "Feature Extraction", "detail": "25 lexical and structural features extracted."},
        {"stage": "ML Inference", "detail": f"Random Forest model applied — phishing probability: {ml_probability * 100:.1f}%."},
        {"stage": "Rule Evaluation", "detail": f"{rule_count} deterministic security rule(s) evaluated; {rule_count} triggered."},
        {"stage": "Threat Intelligence Lookup", "detail": ti_stage_detail},
        {"stage": "Risk Calculation", "detail": f"Composite score calculated: {risk_score}/100 ({risk_level} Risk)."},
        {"stage": "Explanation Generation", "detail": "Structured evidence report assembled."},
    ]

    # ── 7. Optional Global Feature Importance ─────────────────────────────
    global_importance = None
    if model is not None and feature_names is not None:
        try:
            importances = getattr(model, "feature_importances_", None)
            if importances is not None and len(importances) == len(feature_names):
                importance_pairs = sorted(
                    zip(feature_names, importances),
                    key=lambda x: x[1],
                    reverse=True
                )
                global_importance = [
                    {"feature": name, "importance": round(float(imp), 5)}
                    for name, imp in importance_pairs[:10]
                ]
        except Exception as e:
            logger.debug(f"Could not extract feature importances: {e}")

    explanation = {
        "summary": summary,
        "ml_evidence": ml_evidence,
        "rule_evidence": rule_evidence,
        "rule_evidence_summary": {
            "count": rule_count,
            "points_contributed": rule_points,
            "points_maximum": rule_max,
        },
        "feature_evidence": noteworthy_first,
        "risk_contribution": risk_contribution,
        "what_does_this_mean": _what_does_this_mean(risk_level),
        "recommendation": risk_data.get("recommendation", ""),
        "investigation_stages": investigation_stages,
        "threat_intelligence": threat_intel,
        "scan_type": "url",
    }

    if global_importance is not None:
        explanation["global_feature_importance"] = {
            "label": "Global Model Feature Importance",
            "note": (
                "These values reflect the Random Forest model's global feature importance "
                "across all training samples. They indicate which features are generally "
                "most informative for the classifier overall. This is NOT a per-sample "
                "attribution for this specific URL."
            ),
            "top_features": global_importance,
        }

    return explanation


# ---------------------------------------------------------------------------
# Message Explanation Builder
# ---------------------------------------------------------------------------

def build_message_explanation(
    message_preview: str,
    ml_probability: Optional[float],
    ml_prediction: str,
    risk_data: Dict[str, Any],
    detected_indicators: List[Dict[str, Any]],
    url_analyses: List[Dict[str, Any]],
    text_evidence: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """
    Build the full structured explanation for a message analysis result.

    Args:
        message_preview: Short preview of the analyzed message (privacy-safe).
        ml_probability: SMS malicious-message probability (0.0–1.0), or None if offline.
        ml_prediction: Human-readable text model classification.
        risk_data: Dict returned by calculate_message_risk().
        detected_indicators: List of indicator dicts from extract_indicators().
        url_analyses: List of URL analysis result dicts (may be empty).
        text_evidence: List of high-weight vocabulary term dicts (may be empty).

    Returns:
        Structured message explanation dict.
    """
    bd = risk_data.get("calculation_breakdown", {})
    risk_score = risk_data.get("risk_score", 0)
    risk_level = risk_data.get("risk_level", "Low")

    has_urls = bool(url_analyses)
    indicator_count = len(detected_indicators)
    url_count = len(url_analyses)

    # ── 1. Summary ─────────────────────────────────────────────────────────
    prob_str = f"{ml_probability * 100:.1f}%" if ml_probability is not None else "N/A (model offline)"
    summary = (
        f"Analysis of the submitted message produced a composite Risk Score of {risk_score}/100 "
        f"({risk_level} Risk). "
        f"The TF-IDF + Logistic Regression SMS classifier returned a malicious/spam "
        f"probability of {prob_str}. "
        f"{indicator_count} social engineering heuristic indicator(s) were detected."
        + (f" {url_count} embedded URL(s) were analyzed via URL cascade." if has_urls else "")
    )

    # ── 2. ML Evidence (message model) ────────────────────────────────────
    text_ml_points = bd.get("text_ml_points", 0)
    text_ml_max = bd.get("text_ml_max", 55)

    if ml_probability is not None:
        ml_interp = (
            f"The TF-IDF + Logistic Regression model (trained on the UCI SMS Spam Collection) "
            f"estimated a {ml_probability * 100:.1f}% SMS malicious-message probability. "
            f"Elevated malicious/spam probability was produced by the trained model."
            if ml_probability >= 0.50 else
            f"The TF-IDF + Logistic Regression model estimated a {ml_probability * 100:.1f}% "
            f"SMS malicious-message probability ({(1 - ml_probability) * 100:.1f}% consistent "
            f"with legitimate/ham message patterns)."
        )
    else:
        ml_interp = "The text classification model is offline. Analysis relied solely on heuristic patterns."

    ml_evidence = {
        "model": "TF-IDF + Logistic Regression",
        "role": "SMS Malicious-Message / Spam Classifier",
        "dataset": "UCI SMS Spam Collection",
        "malicious_probability": round(ml_probability, 4) if ml_probability is not None else None,
        "malicious_probability_pct": round(ml_probability * 100, 1) if ml_probability is not None else None,
        "predicted_class": ml_prediction,
        "points_contributed": text_ml_points,
        "points_maximum": text_ml_max,
        "interpretation": ml_interp,
        "high_weight_terms": text_evidence[:8] if text_evidence else [],
    }

    # ── 3. Heuristic Indicator Evidence ────────────────────────────────────
    indicator_points = bd.get("indicator_points_applied", 0)
    indicator_max = bd.get("indicator_max", 25)
    indicator_evidence = []
    for ind in detected_indicators:
        indicator_evidence.append({
            "id": ind.get("id", ""),
            "name": ind.get("name", ""),
            "description": ind.get("description", ""),
            "severity": ind.get("severity", ""),
            "severity_score": ind.get("severity_score", 0),
            "match_count": ind.get("match_count", 0),
        })

    # ── 4. URL Cascade Evidence ────────────────────────────────────────────
    url_points = bd.get("url_points_applied", 0)
    url_max = bd.get("url_max", 20)
    url_evidence = []
    if has_urls:
        for ua in url_analyses:
            url_evidence.append({
                "url": ua.get("normalized_url", ua.get("input_url", "")),
                "prediction": ua.get("prediction", ""),
                "risk_score": ua.get("risk_score", 0),
                "risk_level": ua.get("risk_level", ""),
                "triggered_rule_count": len(ua.get("triggered_rules", [])),
                "explanation": ua.get("explanation", {}),
            })

    # ── 5. Risk Contribution ───────────────────────────────────────────────
    risk_contribution = {
        "text_ml_points": text_ml_points,
        "text_ml_points_maximum": text_ml_max,
        "indicator_points": indicator_points,
        "indicator_points_maximum": indicator_max,
        "url_cascade_points": url_points,
        "url_cascade_points_maximum": url_max,
        "total_score": risk_score,
        "total_maximum": 100,
        "formula": bd.get(
            "formula",
            f"Final Risk Score = min(100, Text_ML({text_ml_points}) + "
            f"Indicators({indicator_points}) + URL_Cascade({url_points})) = {risk_score}/100"
        ),
    }

    # ── 6. Investigation Timeline (dynamic — only stages actually performed) ─
    investigation_stages = [
        {"stage": "Input", "detail": "Message text submitted for analysis."},
        {"stage": "Heuristic Indicator Scan", "detail": f"{indicator_count} social engineering pattern(s) evaluated."},
    ]

    if ml_probability is not None:
        investigation_stages.append({
            "stage": "Text ML Inference",
            "detail": f"TF-IDF vectorization + Logistic Regression applied — malicious/spam probability: {ml_probability * 100:.1f}%."
        })
    else:
        investigation_stages.append({
            "stage": "Text ML Inference",
            "detail": "Text model offline — heuristic analysis only."
        })

    if has_urls:
        investigation_stages.append({
            "stage": "URL Extraction & Cascade Analysis",
            "detail": f"{url_count} embedded URL(s) detected and analyzed via URL risk pipeline."
        })
        # Check if threat intelligence was performed on extracted URLs
        ti_runs = [ua.get("threat_intelligence") for ua in url_analyses if ua.get("threat_intelligence")]
        if ti_runs and any(ti.get("enabled") for ti in ti_runs):
            ti_sum = ti_runs[0].get("summary", {})
            st = ti_sum.get("status")
            if st == "success":
                d = ti_sum.get("detections", 0)
                tot = ti_sum.get("total_engines", 0)
                ti_detail = f"VirusTotal queried on embedded link — {d}/{tot} security engines reported malicious activity."
            else:
                ti_detail = f"Threat intelligence lookup on embedded link status: {st}."
            investigation_stages.append({
                "stage": "Threat Intelligence Lookup",
                "detail": ti_detail
            })

    investigation_stages.append({
        "stage": "Composite Risk Calculation",
        "detail": f"Risk Score = {risk_score}/100 ({risk_level} Risk)."
    })
    investigation_stages.append({
        "stage": "Explanation Generation",
        "detail": "Structured evidence report assembled."
    })

    ti_data = None
    if has_urls:
        for ua in url_analyses:
            if ua.get("threat_intelligence"):
                ti_data = ua["threat_intelligence"]
                break

    explanation = {
        "summary": summary,
        "ml_evidence": ml_evidence,
        "indicator_evidence": indicator_evidence,
        "indicator_evidence_summary": {
            "count": indicator_count,
            "points_contributed": indicator_points,
            "points_maximum": indicator_max,
        },
        "url_evidence": url_evidence,
        "url_evidence_summary": {
            "url_count": url_count,
            "points_contributed": url_points,
            "points_maximum": url_max,
            "has_urls": has_urls,
        },
        "risk_contribution": risk_contribution,
        "what_does_this_mean": _what_does_this_mean(risk_level),
        "recommendation": risk_data.get("recommendation", ""),
        "investigation_stages": investigation_stages,
        "threat_intelligence": ti_data,
        "scan_type": "message",
    }

    return explanation


# ---------------------------------------------------------------------------
# Screenshot Explanation Builder (Phase 12)
# ---------------------------------------------------------------------------

def build_screenshot_explanation(
    visual_results: Dict[str, Any],
    ocr_text: Optional[str],
    url_analysis: Optional[Dict[str, Any]],
    ti_data: Optional[Dict[str, Any]],
    risk_breakdown: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Build the full structured explanation for a screenshot analysis result.

    Args:
        visual_results: Dict from analyze_visual_structure (input_fields, buttons, etc.).
        ocr_text: Extracted OCR text (None if OCR unavailable).
        url_analysis: URL analysis result dict (None if no URLs found).
        ti_data: Threat intelligence data from cascaded URL lookup (may be None).
        risk_breakdown: The calculation_breakdown dict from calculate_screenshot_risk().

    Returns:
        Structured screenshot explanation dict matching Phase 9 conventions.
    """
    risk_score = risk_breakdown.get("visual_points", 0) + risk_breakdown.get("text_points", 0) + \
                 risk_breakdown.get("mismatch_points", 0) + risk_breakdown.get("url_cascade_points", 0)
    risk_score = min(100, max(0, risk_score))
    risk_level = "Critical" if risk_score >= 80 else ("High" if risk_score >= 55 else ("Medium" if risk_score >= 25 else "Low"))

    # ── 1. Summary ─────────────────────────────────────────────────────────
    input_fields = visual_results.get("input_fields", 0)
    buttons = visual_results.get("buttons", 0)
    ocr_available = ocr_text is not None

    summary = (
        f"Visual analysis of the uploaded screenshot produced a Risk Score of {risk_score}/100 "
        f"({risk_level} Risk). "
        f"OpenCV contour analysis detected {input_fields} input-like field(s) and {buttons} button-like element(s)."
    )
    if ocr_available and ocr_text:
        summary += f" OCR extracted {len(ocr_text)} character(s) of text for indicator analysis."
    elif not ocr_available:
        summary += " OCR was not available; text-based indicators could not be evaluated."

    # ── 2. Visual Evidence ─────────────────────────────────────────────────
    visual_evidence = {
        "input_fields_detected": input_fields,
        "buttons_detected": buttons,
        "contour_count": visual_results.get("contour_count", 0),
        "visual_points": visual_results.get("visual_points", 0),
        "visual_max": 35,
        "interpretation": (
            f"OpenCV edge detection and contour analysis identified {input_fields} potential "
            f"form input field(s) and {buttons} button-like element(s). These structural "
            f"elements are commonly found in login/credential harvesting pages."
            if input_fields >= 2 or buttons >= 1 else
            f"The screenshot does not exhibit strong structural indicators of a login form. "
            f"{input_fields} input-like and {buttons} button-like contours were detected."
        ),
    }

    # ── 3. OCR Evidence ────────────────────────────────────────────────────
    ocr_evidence = {
        "available": ocr_available,
        "text_length": len(ocr_text) if ocr_text else 0,
        "text_points": risk_breakdown.get("text_points", 0),
        "text_max": 25,
    }

    # ── 4. Risk Contribution ───────────────────────────────────────────────
    risk_contribution = {
        "visual_points": risk_breakdown.get("visual_points", 0),
        "visual_max": 35,
        "text_points": risk_breakdown.get("text_points", 0),
        "text_max": 25,
        "mismatch_points": risk_breakdown.get("mismatch_points", 0),
        "mismatch_max": 20,
        "url_cascade_points": risk_breakdown.get("url_cascade_points", 0),
        "url_cascade_max": 20,
        "total_score": risk_score,
        "total_maximum": 100,
        "formula": risk_breakdown.get("formula", ""),
    }

    # ── 5. Investigation Timeline ──────────────────────────────────────────
    investigation_stages = [
        {"stage": "Input", "detail": "Screenshot image uploaded for visual analysis."},
        {"stage": "Image Validation", "detail": "Image format and size validated via Pillow."},
        {"stage": "Visual Structure Analysis",
         "detail": f"OpenCV contour detection applied — {input_fields} input field(s), {buttons} button(s) identified."},
    ]

    if ocr_available:
        investigation_stages.append({
            "stage": "OCR Text Extraction",
            "detail": f"pytesseract OCR extracted {len(ocr_text) if ocr_text else 0} characters of text."
        })
        investigation_stages.append({
            "stage": "Text Indicator Scan",
            "detail": "OCR text scanned for credential, urgency, financial, and brand keywords."
        })
    else:
        investigation_stages.append({
            "stage": "OCR Text Extraction",
            "detail": "pytesseract not available — OCR analysis skipped."
        })

    if url_analysis:
        url_risk = url_analysis.get("risk_score", 0)
        investigation_stages.append({
            "stage": "URL Cascade Analysis",
            "detail": f"Extracted URL analyzed via existing URL pipeline — risk score: {url_risk}/100."
        })

    # Add TI stage if applicable
    if ti_data and ti_data.get("enabled"):
        ti_sum = ti_data.get("summary", {})
        st = ti_sum.get("status")
        if st == "success":
            d = ti_sum.get("detections", 0)
            t = ti_sum.get("total_engines", 0)
            ti_detail = f"VirusTotal queried on extracted URL — {d}/{t} engines reported malicious."
        else:
            ti_detail = f"Threat intelligence lookup status: {st}."
        investigation_stages.append({"stage": "Threat Intelligence Lookup", "detail": ti_detail})

    investigation_stages.append({
        "stage": "Composite Risk Calculation",
        "detail": f"Risk Score = {risk_score}/100 ({risk_level} Risk)."
    })
    investigation_stages.append({
        "stage": "Explanation Generation",
        "detail": "Structured evidence report assembled."
    })

    explanation = {
        "summary": summary,
        "visual_evidence": visual_evidence,
        "ocr_evidence": ocr_evidence,
        "risk_contribution": risk_contribution,
        "what_does_this_mean": _what_does_this_mean(risk_level),
        "recommendation": risk_breakdown.get("transparency_note", ""),
        "investigation_stages": investigation_stages,
        "threat_intelligence": ti_data,
        "scan_type": "screenshot",
    }

    if url_analysis:
        explanation["url_evidence"] = {
            "url": url_analysis.get("normalized_url", url_analysis.get("input_url", "")),
            "prediction": url_analysis.get("prediction", ""),
            "risk_score": url_analysis.get("risk_score", 0),
            "risk_level": url_analysis.get("risk_level", ""),
        }

    return explanation


# ---------------------------------------------------------------------------
# Email Explanation Builder (Phase 13)
# ---------------------------------------------------------------------------

def build_email_explanation(
    parsed_email: Dict[str, Any],
    header_indicators: List[Dict[str, Any]],
    auth_data: Dict[str, Any],
    subject_indicators: List[Dict[str, Any]],
    body_indicators: List[Dict[str, Any]],
    body_ml_prob: Optional[float],
    body_ml_pred: str,
    attachments: List[Dict[str, Any]],
    attachment_indicators: List[Dict[str, Any]],
    url_analyses: List[Dict[str, Any]],
    html_security_flags: List[Dict[str, Any]],
    risk_data: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Build structured explanation report for .eml email phishing analysis.

    Args:
        parsed_email: Extracted email metadata (headers, domains, body).
        header_indicators: Detected header forensic anomalies.
        auth_data: Authentication dictionary (SPF, DKIM, DMARC statuses and indicators).
        subject_indicators: Subject line social-engineering patterns.
        body_indicators: Body text linguistic and heuristic patterns.
        body_ml_prob: Malicious/spam probability from text classifier proxy.
        body_ml_pred: Class label from text classifier proxy.
        attachments: Inspected attachment metadata list.
        attachment_indicators: Suspicious attachment indicators.
        url_analyses: Cascaded URL analyzer results.
        html_security_flags: Suspicious HTML element detections (e.g. script, iframe).
        risk_data: Return dict from calculate_email_risk().

    Returns:
        Structured explanation dictionary matching Phase 9 conventions.
    """
    risk_score = risk_data.get("risk_score", 0)
    risk_level = risk_data.get("risk_level", "Low")
    bd = risk_data.get("calculation_breakdown", {})

    headers = parsed_email.get("headers", {})
    domains = parsed_email.get("domains", {})
    url_count = len(url_analyses)
    att_count = len(attachments)
    hdr_ind_count = len(header_indicators)
    auth_ind_count = len(auth_data.get("indicators", []))

    # ── 1. Summary ─────────────────────────────────────────────────────────
    summary_parts = [
        f"Analysis of the submitted email file produced a composite Risk Score of {risk_score}/100 ({risk_level} Risk)."
    ]
    if hdr_ind_count > 0:
        summary_parts.append(f"{hdr_ind_count} header forensic anomal{'y' if hdr_ind_count == 1 else 'ies'} detected.")
    if auth_ind_count > 0:
        summary_parts.append(f"Authentication results recorded {auth_ind_count} failure(s) in SPF/DKIM/DMARC.")
    if url_count > 0:
        summary_parts.append(f"{url_count} embedded URL(s) analyzed through the URL risk pipeline.")
    if att_count > 0:
        summary_parts.append(f"{att_count} attachment metadata record(s) inspected.")

    summary = " ".join(summary_parts)

    # ── 2. Header Evidence ─────────────────────────────────────────────────
    header_evidence = {
        "sender": headers.get("from", ""),
        "reply_to": headers.get("reply_to", ""),
        "return_path": headers.get("return_path", ""),
        "sender_domain": domains.get("sender_domain"),
        "reply_to_domain": domains.get("reply_to_domain"),
        "return_path_domain": domains.get("return_path_domain"),
        "indicators": header_indicators,
        "points_contributed": bd.get("header_points", 0),
        "points_maximum": bd.get("header_max", 20),
    }

    # ── 3. Authentication Evidence ─────────────────────────────────────────
    auth_evidence = {
        "has_auth_header": auth_data.get("has_auth_header", False),
        "spf": auth_data.get("spf", "not_present"),
        "dkim": auth_data.get("dkim", "not_present"),
        "dmarc": auth_data.get("dmarc", "not_present"),
        "indicators": auth_data.get("indicators", []),
        "points_contributed": bd.get("auth_points", 0),
        "points_maximum": bd.get("auth_max", 20),
        "note": "Authentication verdicts are extracted directly from the message's Authentication-Results header (no external DNS lookups performed)."
    }

    # ── 4. Subject Evidence ────────────────────────────────────────────────
    subject_evidence = {
        "subject": headers.get("subject", ""),
        "indicators": subject_indicators,
        "points_contributed": bd.get("subject_points", 0),
        "points_maximum": bd.get("subject_max", 15),
    }

    # ── 5. Body & ML Proxy Evidence ────────────────────────────────────────
    body_ml_points = bd.get("body_ml_points", 0)
    body_ml_max = bd.get("body_ml_max", 30)

    if body_ml_prob is not None:
        ml_interp = (
            f"The TF-IDF + Logistic Regression model (trained on the UCI SMS Spam Collection and "
            f"reused here strictly as a proxy signal for message text) estimated a "
            f"{body_ml_prob * 100:.1f}% malicious/spam probability on extracted body text."
        )
    else:
        ml_interp = "Text classification model offline; body analysis relied solely on heuristic indicators."

    body_evidence = {
        "ml_proxy": {
            "model": "TF-IDF + Logistic Regression",
            "role": "SMS Malicious-Message / Spam Classifier (reused as body-analysis proxy)",
            "malicious_probability": round(body_ml_prob, 4) if body_ml_prob is not None else None,
            "malicious_probability_pct": round(body_ml_prob * 100, 1) if body_ml_prob is not None else None,
            "predicted_class": body_ml_pred,
            "interpretation": ml_interp,
            "points_contributed": body_ml_points,
            "points_maximum": body_ml_max,
        },
        "indicators": body_indicators,
        "html_security_flags": html_security_flags,
    }

    # ── 6. Attachment Evidence ─────────────────────────────────────────────
    attachment_evidence = {
        "count": att_count,
        "attachments": attachments,
        "indicators": attachment_indicators,
        "points_contributed": bd.get("attachment_points", 0),
        "points_maximum": bd.get("attachment_max", 15),
        "security_guarantee": "Attachment metadata only was inspected. Attachment binaries are NEVER executed or unpacked."
    }

    # ── 7. URL Cascade Evidence ────────────────────────────────────────────
    url_evidence = []
    ti_runs = []
    for ua in url_analyses:
        ti = ua.get("threat_intelligence")
        if ti:
            ti_runs.append(ti)
        url_evidence.append({
            "url": ua.get("normalized_url", ua.get("input_url", "")),
            "prediction": ua.get("prediction", "Unknown"),
            "risk_score": ua.get("risk_score", 0),
            "risk_level": ua.get("risk_level", "Low"),
            "threat_intelligence": ti
        })

    url_evidence_summary = {
        "count": url_count,
        "max_url_risk": bd.get("max_url_risk_raw", 0),
        "points_contributed": bd.get("url_cascade_points", 0),
        "points_maximum": bd.get("url_cascade_max", 20),
        "strategy": "Highest embedded URL risk score scaled to 20 points (not summed across multiple URLs)."
    }

    # ── 8. Risk Contribution ───────────────────────────────────────────────
    risk_contribution = {
        "header_points": bd.get("header_points", 0),
        "header_max": bd.get("header_max", 20),
        "auth_points": bd.get("auth_points", 0),
        "auth_max": bd.get("auth_max", 20),
        "subject_points": bd.get("subject_points", 0),
        "subject_max": bd.get("subject_max", 15),
        "body_ml_points": bd.get("body_ml_points", 0),
        "body_ml_max": bd.get("body_ml_max", 30),
        "attachment_points": bd.get("attachment_points", 0),
        "attachment_max": bd.get("attachment_max", 15),
        "url_cascade_points": bd.get("url_cascade_points", 0),
        "url_cascade_max": bd.get("url_cascade_max", 20),
        "raw_point_sum": bd.get("raw_point_sum", 0),
        "total_score": risk_score,
        "total_maximum": 100,
        "formula": bd.get("formula", ""),
    }

    # ── 9. Investigation Timeline ──────────────────────────────────────────
    investigation_stages = [
        {"stage": "Input", "detail": "Email (.eml) file submitted for investigation."},
        {"stage": "EML Validation", "detail": "RFC 5322 structure and file size validated in memory."},
        {"stage": "Header Forensics", "detail": f"Evaluated sender, reply-to, return-path ({hdr_ind_count} indicator(s) flagged)."},
        {"stage": "Authentication Analysis", "detail": f"SPF: {auth_data.get('spf')}, DKIM: {auth_data.get('dkim')}, DMARC: {auth_data.get('dmarc')}."},
        {"stage": "Subject Analysis", "detail": f"Subject line analyzed ({len(subject_indicators)} indicator(s) flagged)."},
        {"stage": "Body Extraction & Sanitization", "detail": "Extracted plain text and stripped HTML body elements safely."},
    ]

    if body_ml_prob is not None:
        investigation_stages.append({
            "stage": "Body Text ML Inference",
            "detail": f"TF-IDF + Logistic Regression text proxy applied — malicious probability: {body_ml_prob * 100:.1f}%."
        })

    if url_count > 0:
        investigation_stages.append({
            "stage": "URL Extraction & Cascade Analysis",
            "detail": f"{url_count} embedded link(s) extracted and analyzed via URL risk pipeline (highest risk: {bd.get('max_url_risk_raw', 0)}/100)."
        })
        if ti_runs and any(t.get("enabled") for t in ti_runs):
            ti_active = next(t for t in ti_runs if t.get("enabled"))
            ti_sum = ti_active.get("summary", {})
            st = ti_sum.get("status")
            if st == "success":
                d = ti_sum.get("detections", 0)
                tot = ti_sum.get("total_engines", 0)
                ti_detail = f"VirusTotal queried on embedded link — {d}/{tot} security engines reported malicious."
            else:
                ti_detail = f"Threat intelligence lookup status on embedded link: {st}."
            investigation_stages.append({"stage": "Threat Intelligence Lookup", "detail": ti_detail})

    if att_count > 0:
        investigation_stages.append({
            "stage": "Attachment Metadata Inspection",
            "detail": f"Analyzed metadata for {att_count} attachment(s) ({len(attachment_indicators)} risk indicator(s) flagged)."
        })

    investigation_stages.append({
        "stage": "Composite Risk Calculation",
        "detail": f"Clamped Risk Score = {risk_score}/100 ({risk_level} Risk)."
    })
    investigation_stages.append({
        "stage": "Explanation Generation",
        "detail": "Structured multi-domain evidence report assembled."
    })

    # Optional top-level TI data if any URL had TI
    ti_top = ti_runs[0] if ti_runs else None

    return {
        "summary": summary,
        "header_evidence": header_evidence,
        "auth_evidence": auth_evidence,
        "subject_evidence": subject_evidence,
        "body_evidence": body_evidence,
        "attachment_evidence": attachment_evidence,
        "url_evidence": url_evidence,
        "url_evidence_summary": url_evidence_summary,
        "risk_contribution": risk_contribution,
        "what_does_this_mean": _what_does_this_mean(risk_level),
        "recommendation": risk_data.get("recommendation", ""),
        "investigation_stages": investigation_stages,
        "threat_intelligence": ti_top,
        "scan_type": "email"
    }

