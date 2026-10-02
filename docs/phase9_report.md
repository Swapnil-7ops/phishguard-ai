# Phase 9 Status Report: Advanced Explainable AI Investigation System

**Project:** PhishGuard AI  
**Phase:** 9 — Advanced Explainable AI Investigation System  
**Date:** September 2026  
**Status:** PASS  

---

## 1. Executive Summary

Phase 9 upgraded PhishGuard AI's explainability layer to provide deep, academic-grade, evidence-based investigation breakdowns for both URL and Message analysis vectors. All existing backend engines, ML models, deterministic rules, risk formulas, and API contracts remain strictly preserved.

Every explanation presented to the user is traceable to computed ground-truth evidence:
- 25 continuous and discrete URL structural/lexical features (mapped to human-readable observations with discrete severity tiers)
- Random Forest ML posterior probability (dynamically indexed via `model.classes_`)
- 13 deterministic cybersecurity heuristic rules
- TF-IDF + Logistic Regression text spam/malicious probability
- 8 social engineering pattern heuristics
- Cascaded embedded URL risk analyses
- Bounded linear composite risk calculations (60/40 for URL; 55/25/20 for Message)

---

## 2. Test Verification & Regression Results

Tests were executed using the unified test runner `python run_tests.py` across all test suites:

| Metric | Count |
|---|---|
| **Baseline Tests (Phase 8)** | 93 |
| **New Phase 9 Tests** | 44 |
| **Final Total Tests** | 137 |
| **Passed** | 137 |
| **Failed** | 0 |
| **Skipped** | 0 |
| **Pass Rate** | 100% |

### Test Breakdown by Module

| Module | Test Count | Status |
|---|---|---|
| URL Features (`tests/test_features.py`) | 10 | ✅ PASS |
| Cybersecurity Rules (`tests/test_rules.py`) | 5 | ✅ PASS |
| Risk Engine (`tests/test_risk_engine.py`) | 4 | ✅ PASS |
| Flask REST API (`tests/test_api.py`) | 9 | ✅ PASS |
| Phase 3 ML Pipeline (`tests/test_ml_pipeline.py`) | 10 | ✅ PASS |
| Phase 6 Database & History (`tests/test_database.py`) | 13 | ✅ PASS |
| Phase 7 Text ML Pipeline (`tests/test_text_model.py`) | 10 | ✅ PASS |
| Phase 8 URL Regression (`tests/test_url_regression.py`) | 13 | ✅ PASS |
| Phase 8 Message Regression (`tests/test_message_regression.py`) | 10 | ✅ PASS |
| Phase 8 Model Loading Failure (`tests/test_model_loading_failure.py`) | 9 | ✅ PASS |
| **Phase 9 Explainable AI (`tests/test_explanation.py`)** | **44** | ✅ PASS |
| **Total** | **137** | **100% PASS** |

---

## 3. Files Modified & Added

### Newly Created Files
1. `ml/feature_descriptions.py` — Maps all 25 lexical features to structured observations (`normal`, `noteworthy`, `suspicious`) with explicit non-safety disclaimers for HTTPS.
2. `services/explanation_builder.py` — Structured explanation adapter that consumes outputs of `url_analyzer`, `message_analyzer`, `rule_engine`, `risk_engine`, and `feature_extractor` without modifying any of them.
3. `tests/test_explanation.py` — 44 comprehensive tests covering integration endpoints with Flask `test_client()`, unit tests for feature descriptions, and unit tests for explanation builders.
4. `docs/phase9_report.md` — This report.

### Modified Files
1. `services/url_analyzer.py` — Replaced inline explanation dict with `build_url_explanation()` call; all existing API fields (`prediction`, `ml_prediction`, `confidence`, `risk_score`, `risk_level`, `reasons`, `recommendation`, `triggered_rules`, `calculation_breakdown`, `features`) preserved unchanged.
2. `services/message_analyzer.py` — Replaced inline explanation dict with `build_message_explanation()` call; all existing API fields preserved unchanged.
3. `templates/url_analyzer.html` — Added Phase 9 editorial evidence sections: WHY WAS THIS FLAGGED?, WHAT DOES THIS MEAN?, RISK CONTRIBUTION, INVESTIGATION TIMELINE, TECHNICAL FEATURE INSPECTOR (25 features table), and GLOBAL MODEL FEATURE IMPORTANCE.
4. `templates/message_analyzer.html` — Added Phase 9 editorial evidence sections: WHY WAS THIS FLAGGED?, WHAT DOES THIS MEAN?, RISK CONTRIBUTION, and dynamic INVESTIGATION TIMELINE.
5. `static/js/analyzer.js` — Added `renderP9UrlExplanation()` and `renderP9MessageExplanation()` functions; rendered from backend data exclusively (zero client-side risk calculations).
6. `run_tests.py` — Registered `Phase 9 Explainable AI` test module.
7. `docs/api_documentation.md` — Documented the new `explanation` schema for `/api/analyze-url` and `/api/analyze-message`.
8. `docs/ml_methodology.md` — Added Section 6 on the Phase 9 Explainable AI architecture and feature observation mappings.
9. `docs/limitations.md` — Added Section 7 detailing explainability operational boundaries (no SHAP/LIME, global vs. per-sample distinction).
10. `docs/testing.md` — Added Section 6 documenting Phase 9 test coverage and methodology.

---

## 4. Key Architectural Guarantees Preserved

| Guarantee | Status | Verification Method |
|---|---|---|
| **Backend Changed** | Minimal Adapter Only | New adapter module; existing core services untouched |
| **ML Model Changed** | NO | Existing `.pkl` models loaded as-is; no retraining |
| **Risk Formula Changed** | NO | Formula untouched: URL `min(100, ML*60 + Rule*40)`; Message `min(100, Text*55 + Ind*25 + URL*20)` |
| **Risk Recalculated in Frontend** | NO | Frontend exclusively displays values returned by backend |
| **Rule Engine Refactored** | NO | `services/rule_engine.py` untouched; adapter consumes output |
| **SSRF Safety (No Fetch)** | YES | No HTTP network calls made to submitted URLs |
| **Dangerous Schemes Blocked** | YES | `javascript:`, `data:`, `file:`, etc. rejected before processing |
| **No Hardcoded Secrets** | YES | `.env` git-ignored, `.env.example` clean |
| **Existing API Fields Preserved** | YES | Verified by `test_p9_url_existing_api_fields_preserved` and `test_p9_message_existing_api_fields_preserved` |

---

## 5. Explainability Features Implemented

### 5.1 Evidence Breakdown ("WHY WAS THIS FLAGGED?")
- Dynamically synthesized from actual triggered deterministic rules, notable/suspicious feature observations, and elevated ML posterior probabilities.
- Formatted as an editorial numbered list (`01`, `02`, `03`...) using the PhishGuard visual identity.

### 5.2 Plain-Language Assessment ("WHAT DOES THIS MEAN?")
- Tiered contextual explanations for Low, Medium, High, and Critical risk outcomes.
- Uses strictly probabilistic, evidence-based language (e.g., *"Multiple suspicious structural indicators were detected"*). Never claims absolute certainty.

### 5.3 Point-Allocation Breakdown ("RISK CONTRIBUTION")
- Visualizes actual component points computed by the backend risk engine:
  - **URL:** ML Base (0–60 pts), Rule Evidence (0–40 pts), Total (0–100 pts)
  - **Message:** Text ML (0–55 pts), Indicator Rules (0–25 pts), URL Cascade (0–20 pts), Total (0–100 pts)
- Displays the exact mathematical formula computed server-side.

### 5.4 Dynamic Investigation Timeline
- Vertically sequenced flow reflecting the actual pipeline executed.
- Conditional rendering:
  - A URL scan never displays message-analysis stages.
  - A message without embedded URLs never displays the URL Extraction/Cascade stage (verified by `test_p9_message_investigation_stages_no_url_analysis_for_no_url_message`).

### 5.5 Technical Feature Inspector
- Collapsible table presenting all 25 lexical/structural dimensions extracted from the URL.
- Displays raw feature values alongside human-readable observations and severity classifications (`normal`, `noteworthy`, `suspicious`).
- Distinct from model attribution: clearly documented as structural observations, not per-sample causal drivers.

### 5.6 Global Model Feature Importance
- Read dynamically from the trained Random Forest classifier via `model.feature_importances_`.
- Top-10 features sorted by Gini impurity reduction.
- Strictly labeled as `GLOBAL MODEL FEATURE IMPORTANCE` with a prominent user warning:
  > *"These values reflect the Random Forest model's global feature importance across all training samples... This is NOT a per-sample explanation for this specific URL."*

---

## 6. Known Limitations

1. **Absence of Local Per-Sample Attribution (SHAP / LIME):** Due to computational overhead and dependency constraints, local per-sample Shapley values or LIME surrogate models are not implemented in Phase 9. Explainability relies on transparent feature inspection, rule triggers, and global importance.
2. **Text Model Domain Semantics:** The text classifier is trained on the UCI SMS Spam Collection; its output represents spam and malicious solicitation probability, not pure phishing intent. Composite scoring resolves this by blending heuristics and URL cascades.
3. **No Active Network Inspection:** URLs are analyzed purely through lexical/structural features to avoid SSRF attacks. Server-side redirect chains or dynamic JavaScript payloads cannot be observed.
4. **Out of Scope for Phase 9:** QR detection (quishing), external threat intelligence APIs, screenshot vision analysis, and email header analysis are deferred to subsequent phases as per the project roadmap.

---

## 7. Phase 9 Conclusion

Phase 9 has met all objectives, constraints, and verification requirements. All 137 unit and integration tests pass with zero failures. PhishGuard AI is fully ready for Phase 10 (QR / Quishing Detection).

