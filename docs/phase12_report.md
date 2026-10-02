# Phase 12 Engineering Report: Screenshot / Visual Phishing Detection

**Project:** PhishGuard AI — Explainable AI-Based Multi-Modal Phishing Detection System  
**Phase:** 12 (Screenshot / Visual Phishing Detection)  
**Status:** Completed & Empirically Verified  

---

## 1. Executive Summary

Phase 12 expands PhishGuard AI's multi-modal threat analysis capabilities by introducing a **Screenshot / Visual Phishing Detection** subsystem. Users can upload a screenshot of a suspicious login portal, notification dialog, or phishing page. The subsystem applies explainable computer vision heuristics and optional optical character recognition (OCR) to detect credential harvesting layouts, brand impersonation, and extracted target domains without needing external network access to the destination server.

### Core Architectural Principles
1. **Lightweight & Transparent (No Heavy CNNs):** Uses standard OpenCV contour detection and Pillow image processing. No multi-gigabyte models or fabricated accuracy metrics.
2. **Decoupled OCR with Graceful Degradation:** Integrates an optional `pytesseract` wrapper. If Tesseract binaries are absent from the environment, the system gracefully operates on visual heuristics alone with zero crash.
3. **Zero Outbound Target Access:** Extracted URLs/domains are analyzed using PhishGuard AI's existing static URL Analyzer (25 lexical features + Random Forest + deterministic rules). No sockets, browser automation, or HTTP GET/POST calls are made to destination servers.
4. **Bounded Composite Risk Engine:** Visual points (up to 35 pts), OCR text indicators (up to 25 pts), brand-domain mismatch (up to 20 pts), and cascaded URL risk (up to 20 pts) are synthesized with individual caps and clamped strictly to `[0, 100]`.
5. **Phase 9 Explainable AI Integration:** Produces structured investigation timelines, "Why Was This Flagged?" reports, and transparent risk contribution breakdowns.
6. **Ephemeral Privacy:** Uploaded screenshot bytes are processed strictly in RAM (`io.BytesIO`) and discarded immediately; images are never stored on disk or in the database.

---

## 2. Quantitative Verification Results

Both test suites were executed against the verified baseline to ensure zero regression:

| Test Runner | Baseline (Phase 11) | Post-Phase 12 | Status |
|-------------|---------------------|---------------|--------|
| **pytest** (`python -m pytest -q`) | **283 passed, 0 failed** | **322 passed, 0 failed** (+39 tests) | **100% PASS** |
| **run_tests.py** (unified) | **207 passed, 0 failed** | **246 passed, 0 failed** (+39 tests) | **100% PASS** |

---

## 3. Implementation Details

### 3.1 Visual Analysis Service (`services/screenshot_service.py`)
- `validate_and_load_image`: Validates magic bytes, formats (PNG, JPEG, WEBP, BMP), size limits (<= 10MB), and returns an in-memory Pillow RGB image.
- `analyze_visual_structure`: Applies Gaussian blur, Canny edge detection, and OpenCV contour analysis (`cv2.RETR_TREE`) to identify input fields (horizontal rectangles), buttons (prominent action boxes), and UI clutter.
- `extract_ocr_text`: Graceful wrapper around `pytesseract.image_to_string`. Catches missing binary exceptions safely.
- `extract_text_indicators`: Categorizes extracted text into credential keywords, urgency patterns, financial terms, and recognized brand targets.
- `extract_domains_and_urls`: Uses regex to extract fully-qualified URLs and bare domain tokens from OCR text.
- `correlate_brand_and_domain`: Flags brand-domain discrepancies (e.g. text mentions "PayPal" but domain is `paypa1.tk`).
- `process_screenshot_analysis`: Master orchestrator synthesizing all components into a standardized envelope.

### 3.2 Risk Engine Extension (`services/risk_engine.py`)
Added `calculate_screenshot_risk()`:
```python
vis_capped = min(int(visual_points), 35)
txt_capped = min(int(text_points), 25)
mis_capped = min(int(mismatch_points), 20)
url_capped = min(int(round(url_cascade_points * 0.20)), 20)

final_score = min(100, max(0, vis_capped + txt_capped + mis_capped + url_capped))
```

### 3.3 Explainable AI Extension (`services/explanation_builder.py`)
Added `build_screenshot_explanation()`:
- Sets `scan_type="screenshot"`.
- Formulates an investigation timeline dynamically reflecting which stages were executed (Image Validation, Visual Structure Analysis, OCR Extraction / Fallback, Text Indicator Scan, URL Cascade Analysis, Threat Intelligence Lookup, Composite Scoring).

### 3.4 REST API Endpoint (`routes/message_routes.py`)
- `POST /api/analyze-screenshot`: Accepts multipart form uploads under the `image` field.
- Executes `process_screenshot_analysis()`.
- Persists normalized metadata to MongoDB via `save_scan(input_type="screenshot")`.
- Returns full data envelope with HTTP 200, or HTTP 400/413 on validation failures.

### 3.5 Frontend Interface
- `templates/screenshot_analyzer.html`: Replaced obsolete purple placeholder with PhishGuard AI's retro-modern editorial identity (Warm Cream, Deep Teal, Coral, Terracotta).
- `static/js/screenshot_analyzer.js`: Handles drag-and-drop file upload, in-memory preview, AJAX submission, risk hero gauge rendering, visual metric cards, OCR previews, and timeline rendering.

---

## 4. Test Coverage Summary (`tests/test_screenshot.py`)

39 dedicated tests covering:
- PNG, JPEG, WEBP image loading and verification.
- Corruption, truncated header, oversized, and invalid format handling.
- Blank image vs. synthetic login form contour detection.
- Visual score bounding at 35 points max.
- OCR graceful degradation when pytesseract/Tesseract is absent.
- Credential, urgency, financial, and brand keyword detection.
- Bare domain and URL regex extraction.
- Brand-domain mismatch penalty (+20 pts) vs. legitimate match (0 pts).
- Individual and composite risk engine score caps.
- Structured explanation generation and timeline accuracy.
- Complete orchestration with mocked OCR and cascaded URL Analyzer.
- Security assertions verifying zero outbound HTTP requests to target URLs.
- Privacy assertions verifying zero leaked image files in temporary directories.
- REST API contract validation (200 OK, 400 Bad Request, 413 Payload Too Large, MongoDB scan ID persistence).
