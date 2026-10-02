"""
risk_engine.py - Explainable Risk Scoring Engine

WHAT: Synthesizes machine learning probabilistic confidence and heuristic rule detections
     into an interpretable 0-100 composite Risk Score and categorical Risk Level.
WHY: Academic and operational cybersecurity requires distinguishing between:
       - Model Confidence (statistical posterior probability of the classifier)
       - Risk Score (project's normalized composite indicator blending ML and rule severity)
HOW:
  Formula:
    ML Base Contribution (0 to 60 pts) = round(ml_phishing_probability * 60)
    Rule Indicator Contribution (0 to 40 pts) = min(sum(rule.score_impact for rule in triggered_rules), 40)
    Composite Risk Score (0 to 100) = min(100, ML Base + Rule Contribution)
INPUT: ml_probability (float [0.0, 1.0]), triggered_rules (list of dicts).
OUTPUT: Dictionary with risk_score, risk_level, recommendation, calculation breakdown, and explainability items.
LIMITATIONS:
  - The Risk Score is PhishGuard AI's normalized internal index, NOT an ISO/NIST standardized metric.
  - Linear combination with a 60/40 weighting assumption is designed for balanced explainability.
"""
import math
from typing import Dict, Any, List, Optional


def _clamp_probability(prob: Any) -> float:
    """
    Defensively clamp a probability value to [0.0, 1.0].

    Converts None, NaN, and ±infinity to 0.0 rather than raising TypeError
    or producing a score outside the 0-100 range.  Valid float inputs in
    [0.0, 1.0] pass through unchanged.
    """
    try:
        v = float(prob)
    except (TypeError, ValueError):
        return 0.0
    if not math.isfinite(v):
        return 0.0
    return max(0.0, min(1.0, v))


def determine_risk_level(score: int) -> str:
    """
    Categorize score into standard operational tiers.
      0 - 24:   Safe / Low Risk
      25 - 54:  Moderate / Suspicious
      55 - 79:  High Risk
      80 - 100: Critical Risk
    """
    if score >= 80:
        return "Critical"
    elif score >= 55:
        return "High"
    elif score >= 25:
        return "Medium"
    else:
        return "Low"


def generate_recommendation(risk_level: str, triggered_rules: List[Dict[str, Any]]) -> str:
    """Produce actionable security advice tailored to the findings."""
    has_ip = any(r.get('rule_id') == 'URL_IP' for r in triggered_rules)
    has_at = any(r.get('rule_id') == 'URL_AT' for r in triggered_rules)
    has_shortener = any(r.get('rule_id') == 'URL_SHORTENER' for r in triggered_rules)

    if risk_level == "Critical":
        rec = "CRITICAL ALERT: Strong evidence of an active phishing or credential harvesting attack. DO NOT navigate to this site, do NOT input usernames, passwords, OTPs, or credit card details. Report this link to your security team or mail administrator."
    elif risk_level == "High":
        rec = "HIGH RISK: Multiple suspicious attributes detected. Avoid entering passwords, personal information, or downloading files until identity is verified via an out-of-band communication channel."
    elif risk_level == "Medium":
        rec = "SUSPICIOUS / ELEVATED RISK: The resource demonstrates structural anomalies (e.g. non-standard TLD, subdomain nesting, or lack of transport security). Exercise caution and verify the top-level organization."
    else:
        rec = "LOW RISK: The analyzed attributes align with legitimate web resource profiles. Maintain standard security awareness—never provide credentials if prompted unexpectedly."

    if has_ip:
        rec += " Special note: Direct IP address access was detected."
    elif has_at:
        rec += " Special note: URL uses @ symbol redirection spoofing."
    elif has_shortener:
        rec += " Special note: The URL is masked behind a link shortener."

    return rec


def calculate_url_risk(
    ml_probability: float,
    triggered_rules: List[Dict[str, Any]],
    features: Dict[str, Any],
    threat_intel: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Calculate the transparent, explainable composite risk score.

    Args:
        ml_probability: Posterior probability of phishing class [0.0, 1.0].
        triggered_rules: List of rule dicts matching features.
        features: Extracted feature dictionary.
        threat_intel: Optional normalized threat intelligence dictionary.

    Returns:
        Structured dictionary containing:
          - risk_score: int [0, 100]
          - risk_level: 'Low' | 'Medium' | 'High' | 'Critical'
          - recommendation: str
          - calculation_breakdown: detailed components
          - reasons: top explainable items
    """
    # Defensively validate and clamp ml_probability to [0.0, 1.0]
    ml_probability = _clamp_probability(ml_probability)

    # 1. ML Contribution (60% weight cap)
    ml_base = int(round(ml_probability * 60))

    # 2. Rule Impact Contribution (40% weight cap)
    raw_rule_sum = sum(int(r.get("score_impact", 0)) for r in triggered_rules)
    rule_contribution = min(raw_rule_sum, 40)

    # 3. Optional Bounded Threat Intelligence Evidence (0, 8, or 15 pts)
    ti_points = 0
    ti_status = "not_configured"
    ti_detections = 0
    ti_engines = 0
    if threat_intel and isinstance(threat_intel, dict):
        summary = threat_intel.get("summary", {})
        ti_status = summary.get("status", "not_configured")
        ti_detections = int(summary.get("detections", 0))
        ti_engines = int(summary.get("total_engines", 0))

        # Threat Intelligence must NEVER modify existing local risk score when provider is unavailable,
        # unconfigured, timed out, rate limited, errored, or has zero detections.
        if ti_status == "success" and ti_detections > 0:
            if ti_detections >= 5:
                ti_points = 15
            else:
                ti_points = 8

    # 4. Final Composite Score
    final_score = min(100, max(0, ml_base + rule_contribution + ti_points))
    risk_level = determine_risk_level(final_score)
    recommendation = generate_recommendation(risk_level, triggered_rules)

    # 5. Generate structured explainability reasons
    reasons = []
    if ml_probability >= 0.70:
        reasons.append(f"Random Forest Classifier detected high statistical alignment with known phishing campaigns ({ml_probability*100:.1f}% confidence).")
    elif ml_probability <= 0.30:
        reasons.append(f"Random Forest Classifier found strong similarity to benign/legitimate domains ({(1 - ml_probability)*100:.1f}% legitimate confidence).")
    else:
        reasons.append(f"Random Forest Classifier reported ambiguous lexical characteristics ({ml_probability*100:.1f}% phishing probability).")

    # Add specific rule findings sorted by severity
    sorted_rules = sorted(triggered_rules, key=lambda x: x.get('score_impact', 0), reverse=True)
    for r in sorted_rules[:4]:
        reasons.append(f"{r['name']} (+{r['score_impact']} pts): {r['description']}")

    # Add Threat Intelligence corroboration reason if positive detections exist
    if ti_points > 0:
        reasons.append(f"Threat Intelligence: External security engines reported {ti_detections} malicious detection(s) across {ti_engines} engines (+{ti_points} pts).")

    formula_str = (
        f"Final Risk Score = min(100, ML_Base({ml_base}) + Rule_Impact({rule_contribution}) + Threat_Intel({ti_points})) = {final_score}/100"
        if ti_points > 0 else
        f"Final Risk Score = min(100, ML_Base({ml_base}) + Rule_Impact({rule_contribution})) = {final_score}/100"
    )

    breakdown = {
        "ml_probability": round(ml_probability, 4),
        "ml_base_points": ml_base,
        "ml_max_possible": 60,
        "raw_rule_points": raw_rule_sum,
        "rule_points_applied": rule_contribution,
        "rule_max_possible": 40,
        "threat_intel_points": ti_points,
        "threat_intel_status": ti_status,
        "threat_intel_detections": ti_detections,
        "formula": formula_str,
        "transparency_note": "Score is derived from the Random Forest probability distribution (60%), deterministic security rules (40%), and optional bounded threat intelligence corroboration."
    }

    return {
        "risk_score": final_score,
        "risk_level": risk_level,
        "recommendation": recommendation,
        "reasons": reasons,
        "calculation_breakdown": breakdown
    }


def calculate_message_risk(
    text_probability: float,
    indicators_detected: List[Dict[str, Any]],
    max_url_risk: int = 0
) -> Dict[str, Any]:
    """
    Calculate composite risk score for text message / email analysis.

    Weighting:
      - Text ML contribution (up to 55 pts): round(text_probability * 55)
      - Rule indicators contribution (up to 25 pts): min(sum(indicators), 25)
      - Cascaded URL risk (up to 20 pts): min(round(max_url_risk * 0.20), 20)
      - Formula: min(100, max(0, text_ml + indicators + url_risk))
    """
    # Defensively validate and clamp text_probability to [0.0, 1.0]
    text_probability = _clamp_probability(text_probability)

    # 1. Text ML Base Contribution (0 to 55 pts)
    text_ml_base = int(round(text_probability * 55))

    # 2. Rule / Heuristic Indicators Contribution (0 to 25 pts)
    pattern_sum = sum(int(ind.get("severity_score", 5)) for ind in indicators_detected)
    pattern_contribution = min(max(0, pattern_sum), 25)

    # 3. Cascaded URL Risk Contribution (0 to 20 pts)
    url_contribution = min(max(0, int(round(max_url_risk * 0.20))), 20)

    # 4. Composite Risk Score
    final_score = min(100, max(0, text_ml_base + pattern_contribution + url_contribution))
    risk_level = determine_risk_level(final_score)

    if final_score >= 80:
        rec = "CRITICAL SOCIAL ENGINEERING THREAT: Severe malicious indicators, credential/OTP demands, or high-risk embedded links detected. Do NOT click any links, do NOT reply or provide sensitive information."
    elif final_score >= 55:
        rec = "HIGH SOCIAL ENGINEERING RISK: Urgent demands, threat language, or coercive patterns detected. Exercise caution and verify sender through secondary out-of-band communication."
    elif final_score >= 25:
        rec = "MODERATE SUSPICION: Contains typical phishing wording or link call-to-action. Verify sender identity and inspect all embedded links before taking action."
    else:
        rec = "LOW RISK: Standard linguistic indicators consistent with legitimate communication."

    breakdown = {
        "text_ml_probability": round(text_probability, 4),
        "text_ml_points": text_ml_base,
        "text_ml_max": 55,
        "indicator_points_raw": pattern_sum,
        "indicator_points_applied": pattern_contribution,
        "indicator_max": 25,
        "cascaded_url_risk": max_url_risk,
        "url_points_applied": url_contribution,
        "url_max": 20,
        "formula": f"Final Risk Score = min(100, Text_ML({text_ml_base}) + Indicators({pattern_contribution}) + URL_Cascade({url_contribution})) = {final_score}/100"
    }

    return {
        "risk_score": final_score,
        "risk_level": risk_level,
        "recommendation": rec,
        "calculation_breakdown": breakdown
    }


def calculate_screenshot_risk(
    visual_points: int,
    text_points: int = 0,
    mismatch_points: int = 0,
    url_cascade_points: int = 0,
) -> Dict[str, Any]:
    """
    Calculate composite risk score for screenshot / visual phishing analysis.

    Bounded contributions:
      - Visual structure indicators (up to 35 pts): form fields, buttons, cluttered layout.
      - OCR text indicators (up to 25 pts): credential, urgency, financial keywords.
      - Brand-domain mismatch (up to 20 pts): brand keyword found but not in extracted domain.
      - Cascaded URL risk (up to 20 pts): min(round(url_cascade_points * 0.20), 20).
      - Formula: min(100, max(0, visual + text + mismatch + url_cascade)).

    Args:
        visual_points: Points from visual heuristic analysis (capped at 35 internally).
        text_points: Points from OCR text indicator detection (capped at 25 internally).
        mismatch_points: Points from brand-domain mismatch detection (capped at 20 internally).
        url_cascade_points: Raw risk score from existing URL analyzer (0-100); scaled to 0-20.

    Returns:
        Structured dictionary with risk_score, risk_level, recommendation, and breakdown.
    """
    # Enforce individual caps with non-negativity
    vis_capped = min(max(0, int(visual_points)), 35)
    txt_capped = min(max(0, int(text_points)), 25)
    mis_capped = min(max(0, int(mismatch_points)), 20)
    url_capped = min(max(0, int(round(url_cascade_points * 0.20))), 20)

    final_score = min(100, max(0, vis_capped + txt_capped + mis_capped + url_capped))
    risk_level = determine_risk_level(final_score)

    if final_score >= 80:
        rec = ("CRITICAL VISUAL THREAT: The screenshot exhibits strong visual indicators "
               "of a phishing page (login form, credential prompts, brand impersonation). "
               "Do NOT enter any credentials or personal information.")
    elif final_score >= 55:
        rec = ("HIGH VISUAL RISK: Multiple suspicious visual elements detected. "
               "Verify the website URL independently before interacting with any form fields.")
    elif final_score >= 25:
        rec = ("MODERATE VISUAL SUSPICION: Some visual patterns associated with phishing "
               "were detected. Exercise caution and verify the source.")
    else:
        rec = ("LOW VISUAL RISK: No significant phishing visual indicators were detected. "
               "Maintain standard security awareness.")

    formula_str = (
        f"Final Risk Score = min(100, Visual({vis_capped}) + Text({txt_capped}) "
        f"+ Mismatch({mis_capped}) + URL_Cascade({url_capped})) = {final_score}/100"
    )

    breakdown = {
        "visual_points": vis_capped,
        "visual_max": 35,
        "text_points": txt_capped,
        "text_max": 25,
        "mismatch_points": mis_capped,
        "mismatch_max": 20,
        "url_cascade_raw": int(url_cascade_points),
        "url_cascade_points": url_capped,
        "url_cascade_max": 20,
        "formula": formula_str,
        "transparency_note": (
            "Score is derived from lightweight OpenCV visual heuristics, "
            "optional OCR text indicators, brand-domain correlation, "
            "and cascaded URL risk from the existing URL analysis pipeline."
        ),
    }

    return {
        "risk_score": final_score,
        "risk_level": risk_level,
        "recommendation": rec,
        "calculation_breakdown": breakdown,
    }


def calculate_email_risk(
    header_points: int,
    auth_points: int = 0,
    subject_points: int = 0,
    body_ml_points: int = 0,
    attachment_points: int = 0,
    url_cascade_points: int = 0,
    max_url_risk: int = 0,
    body_ml_prob: Optional[float] = None
) -> Dict[str, Any]:
    """
    Calculate composite risk score for .eml email phishing analysis.

    Bounded Point Allocations (NOT percentages):
      - Header indicators: up to 20 points (Reply-To mismatch, Return-Path divergence, formatting anomalies)
      - Authentication indicators: up to 20 points (SPF/DKIM/DMARC failure evidence)
      - Subject indicators: up to 15 points (Urgency, credential, financial pressure)
      - Body ML analysis: up to 30 points (TF-IDF + Logistic Regression proxy signal)
      - Attachment metadata: up to 15 points (Executable, script, macro extensions, double extensions)
      - URL cascade: up to 20 points (Scaled from highest URL risk: min(round(max_url_risk * 0.20), 20))

    Normalization / Clamping:
      Raw point sum can reach 120 points; final score is strictly clamped to [0, 100]:
      Final Risk Score = min(100, max(0, Header + Auth + Subject + Body + Attachment + URL_Cascade))

    Args:
        header_points: Points from header analysis (capped internally at 20).
        auth_points: Points from authentication header forensics (capped internally at 20).
        subject_points: Points from subject social-engineering triggers (capped internally at 15).
        body_ml_points: Points from body text classifier proxy (capped internally at 30).
        attachment_points: Points from attachment metadata checks (capped internally at 15).
        url_cascade_points: Scaled points from highest risk URL (capped internally at 20).
        max_url_risk: Raw highest risk score across all extracted URLs (0-100).
        body_ml_prob: Statistical posterior probability from text classifier proxy (or None).

    Returns:
        Structured dictionary with risk_score, risk_level, recommendation, and calculation_breakdown.
    """
    # Enforce individual point allocation bounds
    hdr_capped = min(max(0, int(header_points)), 20)
    auth_capped = min(max(0, int(auth_points)), 20)
    subj_capped = min(max(0, int(subject_points)), 15)
    body_capped = min(max(0, int(body_ml_points)), 30)
    att_capped = min(max(0, int(attachment_points)), 15)
    url_capped = min(max(0, int(url_cascade_points)), 20)

    # Centralized normalization / clamping to [0, 100]
    raw_sum = hdr_capped + auth_capped + subj_capped + body_capped + att_capped + url_capped
    final_score = min(100, max(0, raw_sum))
    risk_level = determine_risk_level(final_score)

    if final_score >= 80:
        rec = (
            "CRITICAL EMAIL THREAT: Strong converging evidence of a spear-phishing or credential-harvesting "
            "campaign (e.g. authentication failure, deceptive headers, high-risk links, or executable attachments). "
            "DO NOT click any links, do NOT download or open attachments, and report this message immediately to your SOC or security administrator."
        )
    elif final_score >= 55:
        rec = (
            "HIGH EMAIL RISK: Multiple suspicious indicators detected across message headers, body wording, "
            "or embedded links. Avoid taking requested actions until the sender's identity is independently verified out-of-band."
        )
    elif final_score >= 25:
        rec = (
            "MODERATE SUSPICION: Minor structural discrepancies, link calls-to-action, or social-engineering "
            "language detected. Inspect the sender domain and links carefully before proceeding."
        )
    else:
        rec = (
            "LOW RISK: Email headers and content are consistent with legitimate communications. "
            "Standard security hygiene applies—never share passwords or credentials unexpectedly."
        )

    formula_str = (
        f"Final Risk Score = min(100, Header({hdr_capped}) + Auth({auth_capped}) + "
        f"Subject({subj_capped}) + Body_ML({body_capped}) + Attachment({att_capped}) + "
        f"URL_Cascade({url_capped})) = {final_score}/100"
    )

    breakdown = {
        "header_points": hdr_capped,
        "header_max": 20,
        "auth_points": auth_capped,
        "auth_max": 20,
        "subject_points": subj_capped,
        "subject_max": 15,
        "body_ml_points": body_capped,
        "body_ml_max": 30,
        "body_ml_probability": round(body_ml_prob, 4) if body_ml_prob is not None else None,
        "attachment_points": att_capped,
        "attachment_max": 15,
        "url_cascade_points": url_capped,
        "url_cascade_max": 20,
        "max_url_risk_raw": max_url_risk,
        "raw_point_sum": raw_sum,
        "formula": formula_str,
        "transparency_note": (
            "Score is derived from bounded risk point allocations across 6 evidence domains: "
            "header forensics (≤20 pts), authentication failures (≤20 pts), subject triggers (≤15 pts), "
            "body text classifier proxy (≤30 pts), attachment metadata (≤15 pts), and highest embedded URL risk (≤20 pts). "
            "The sum (up to 120 pts) is strictly clamped to [0, 100]."
        )
    }

    return {
        "risk_score": final_score,
        "risk_level": risk_level,
        "recommendation": rec,
        "calculation_breakdown": breakdown
    }

