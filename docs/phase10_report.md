# Phase 10 — QR / Quishing Detection Report

**Project:** PhishGuard AI  
**Phase:** Phase 10 — QR / Quishing Detection Subsystem  
**Date:** 2026-09-27  
**Status:** COMPLETE (PASS)  

---

## 1. Objective

Add QR-code based phishing detection ("Quishing") to PhishGuard AI by decoding incoming QR code images in server memory and seamlessly feeding the decoded URL into the existing URL Analysis pipeline.

**Core Principle:** QR is strictly an input modality. The system does not create a separate QR ML model, does not alter the 25 URL features, does not modify existing risk formulas, and never visits or executes decoded destinations.

---

## 2. Architecture & Data Flow

```
[ Uploaded QR Image (PNG/JPG/WEBP) ]
               │
               ▼
    Image Validation & Memory Buffer (Pillow)
               │ (verify image integrity, dimension bounds <= 4096px)
               ▼
     OpenCV QRCodeDetector (_detect_with_fallbacks)
               │ (multi-scale search: 1.0, grayscale, 0.75, 0.5, 0.6, 1.25)
               ▼
     [ Decoded String Payload ]
               │
      Dangerous Scheme Check?
      ├── YES (javascript:, data:, file:, vbscript:, about:)
      │     └──> Immediately return: prediction="Blocked", risk=100, Critical Risk
      │
      URL-like Syntax Check?
      ├── NO (plain text, notes, wifi strings)
      │     └──> Return: payload_type="text", prediction="Informational", risk=0
      │
      └── YES (http://, https://, or domain.tld/...)
            │
            ▼
    Existing URL Analyzer (validate_and_normalize_url + analyze_url)
            ├── 25 Lexical & Structural Features
            ├── Random Forest Classifier (Inference & Posterior Probability)
            ├── 13 Deterministic Security Rules
            ├── Composite Risk Engine (ML 60% + Rules 40%)
            └── Phase 9 Explainable AI Engine
                     │
                     ▼
           [ Response Payload ]
                     │
                     ▼
    Persistence Layer (save_scan with scan_type='qr', input_type='image')
```

---

## 3. QR Decoder Implementation

- **Engine:** OpenCV `cv2.QRCodeDetector` from `opencv-python-headless>=5.0.0`.
- **Pre-validation:** Pillow (`PIL.Image.open()`) verifies binary headers and checks for truncation or corruption before passing to the computer vision matrix.
- **Multi-Strategy Detection:** Handles varying finder pattern densities and resolution variations via `_detect_with_fallbacks()`:
  1. Direct BGR array detection
  2. Grayscale contrast fallback
  3. Multi-scale search (scaling factors: 0.75, 0.50, 0.60, 1.25) using area/linear interpolation.
- **Single-QR Reliability:** Dedicated to robust primary QR recognition rather than speculative multi-code risk aggregation.

---

## 4. Supported Image Formats & Boundaries

| Parameter | Specification | Enforcement |
|---|---|---|
| Supported Extensions | `.png`, `.jpg`, `.jpeg`, `.webp`, `.bmp`, `.gif` | `config.ALLOWED_IMAGE_EXTENSIONS` |
| Maximum Upload Size | 10 MB (10,485,760 bytes) | Enforced in route handler (HTTP 413) |
| Max Dimension Bound | 4096 × 4096 px | Auto-downscaled in memory (Pillow LANCZOS) |
| Image Lifecycle | In-memory stream only | **Discarded immediately** after decode; never saved to disk |

---

## 5. Payload Handling & Classification

1. **Dangerous Schemes:** Any payload starting with `javascript:`, `data:`, `file:`, `vbscript:`, `about:`, `blob:`, `chrome:`, or `resource:` is intercepted and blocked:
   - `payload_type`: `"dangerous_scheme"`
   - `prediction`: `"Blocked"`
   - `risk_score`: `100`
   - `risk_level`: `"Critical"`
   - Decoded payload truncated to 100 characters in API response for safety.
2. **Web URLs:** Payloads matching HTTP/HTTPS or scheme-less domains (e.g. `domain.com/path`):
   - `payload_type`: `"url"`
   - Passed directly to `services.url_analyzer.analyze_url()`.
3. **Plain Text:** Non-URL strings without valid domain structures (e.g. contact cards, arbitrary sentences):
   - `payload_type`: `"text"`
   - `prediction`: `"Informational"`
   - `risk_score`: `0`
   - `risk_level`: `"Low"`
   - `url_analysis`: `null` (No fabricated scores or false alarms).

---

## 6. URL Analyzer & Explainability Reuse

- **Single Source of Truth:** `services.url_analyzer.analyze_url()` is the sole engine executing feature extraction, Random Forest inference, rule evaluation, and composite risk scoring.
- **Phase 9 Explainability Preservation:** All six Phase 9 explanation structures are returned for URL QR scans:
  - *WHY WAS THIS FLAGGED?* (Structured feature and rule observations)
  - *WHAT DOES THIS MEAN?* (Human-readable cybersecurity summary)
  - *RISK CONTRIBUTION* (Exact points breakdown: `ML_Base(60)` + `Rules(40)`)
  - *INVESTIGATION TIMELINE* (Chronological step-by-step pipeline audit)
  - *TECHNICAL FEATURE INSPECTOR* (All 25 URL features with normal/suspicious ratings)
  - *GLOBAL MODEL FEATURE IMPORTANCE* (Dataset-level Random Forest Gini ranking)

---

## 7. Security Controls & SSRF Protection

1. **Static Analysis Only:** QR analysis never issues HTTP GET/POST requests to the decoded URL.
2. **No Browser or Process Spawning:** No Selenium, Playwright, Chrome, or subprocesses are used.
3. **Network Isolation Verified:** Unit tests explicitly mock `requests.get`, `requests.post`, and `urllib.request.urlopen` and assert zero outbound calls during QR processing.
4. **Dangerous Scheme Interception:** Payloads targeting internal file systems (`file:///etc/passwd`) or browser execution contexts (`javascript:`) never reach the URL analyzer.
5. **Privacy Sanitization:** Decoded URLs stored in scan history are scrubbed by `sanitize_scan_input(raw_input, "qr")` to strip embedded passwords, query tokens, and sensitive parameters.

---

## 8. API Specification

- **Endpoint:** `POST /api/analyze-qr`
- **Content-Type:** `multipart/form-data`
- **Field:** `image` (binary file)
- **Response Structure:** Standardized PhishGuard envelope:
  ```json
  {
    "success": true,
    "data": {
      "success": true,
      "qr_detected": true,
      "qr_count": 1,
      "payload_type": "url",
      "decoded_payload": "...",
      "decoded_url": "...",
      "prediction": "...",
      "risk_score": 0,
      "risk_level": "...",
      "ml_probability": 0.0,
      "url_analysis": { ... },
      "scan_id": "..."
    }
  }
  ```

---

## 9. Database Integration

- **Scan Type:** Saved with `input_type="qr"`.
- **Model Attribution:** Stored as `"Random Forest (via QR Decode)"`.
- **Dashboard Telemetry:** Integrated into scan metrics and history counters without requiring separate collections or database migrations.
- **In-Memory Fallback:** Fully operational when local MongoDB daemon is offline.

---

## 10. Frontend Implementation

- **Template:** `templates/qr_scanner.html` rebuilt from scratch using the official PhishGuard editorial palette:
  - Deep Teal: `#244855`
  - Coral: `#E64833`
  - Terracotta: `#874F41`
  - Muted Aqua: `#90AEAD`
  - Warm Cream: `#FBE9D0`
- **Features:**
  - Drag-and-drop zone with instant client-side preview via `FileReader`
  - Real-time progress updates and status badges
  - Dedicated payload preview card with security notice
  - Dynamic result switching (URL Analysis card vs Plain Text informational card)
  - Full Phase 9 Explainable AI investigation panels embedded inline
- **Navigation:** Added "QR Scanner" icon and link in `templates/base.html`.
- **History Filter:** Added "QR Code" option to the filter dropdown in `templates/history.html`.

---

## 11. Automated Test Results

### Baseline Execution (Before Phase 10)
- **Unified Test Runner (`run_tests.py`):**
  - Total: 137
  - Passed: 137
  - Failed: 0
  - Skipped: 0

### Phase 10 New QR Test Suite (`tests/test_qr.py`)
- **New Tests Added:** 31 tests covering:
  - 10 Decoding & input validation tests (HTTPS, HTTP, IP, malformed, text, empty, corrupt, unsupported, oversized, blank image)
  - 6 Dangerous scheme rejection tests (javascript, data, file, vbscript, about, helper)
  - 7 Pipeline integration tests (URL analyzer delegation, 25 features, RF model, rules, risk engine, Phase 9 explanation, score bounds [0, 100])
  - 2 Database persistence tests (scan saving, history retrieval, credential redaction)
  - 3 Security & network isolation tests (requests/urllib mock assertions, process isolation, pre-analysis filtering)
  - 3 REST API endpoint tests (valid 200, missing file 400, corrupt image handled)

### Final Execution (After Phase 10)
- **Unified Test Runner (`run_tests.py`):**
  - **Total:** 168
  - **Passed:** 168
  - **Failed:** 0
  - **Skipped:** 0
- **Pytest Suite (`pytest -q`):**
  - **Total:** 244
  - **Passed:** 244
  - **Failed:** 0
  - **Skipped:** 0

---

## 12. Manual Smoke-Test Verification

| # | Test Scenario | Input | Expected Output | Actual Result |
|---|---|---|---|---|
| 1 | Navigation | Click "QR Scanner" in sidebar | `/qr-scanner` page renders with editorial theme | PASS |
| 2 | Legitimate QR | QR encoding `https://github.com/login` | Decoded, risk ~8/100, "Legitimate", Phase 9 panels shown | PASS |
| 3 | Phishing QR | QR encoding `http://192.168.1.1/paypal/login` | Decoded, risk >= 75/100, "Suspicious"/"Phishing", rules triggered | PASS |
| 4 | Dangerous Scheme | QR encoding `javascript:alert(1)` | Blocked immediately, prediction "Blocked", risk 100/100 | PASS |
| 5 | Plain Text QR | QR encoding `WiFi:S:MyNetwork;P:Secret;` | Payload displayed, prediction "Informational", risk 0/100 | PASS |
| 6 | Image with No QR | Blank white square image | Controlled error: "No QR code could be recognized" | PASS |
| 7 | Scan History | View `/history` with filter "QR Code" | Previously analyzed QR scans appear with decoded URL & risk | PASS |

---

## 13. Known Limitations & Future Scope

1. **Single-QR Scope:** Processes the primary QR code in the uploaded image. Multi-QR composition is deferred to prevent ungrounded risk aggregation.
2. **Severe Distortion:** Extreme perspective skew (> 60°), heavy motion blur, or pixelation may evade detection.
3. **No Network Scraping:** PhishGuard AI intentionally does not follow HTTP redirects, download remote landing pages, or resolve DNS records, preserving complete SSRF immunity.
4. **Future Scope (Phase 11+):** Threat intelligence integration (e.g. VirusTotal/Google Safe Browsing APIs) for external corroboration.
