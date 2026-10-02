# PhishGuard AI - Testing & Verification Strategy

## 1. Test Architecture

The test suite uses **Python's built-in `unittest` framework** (no third-party test runners required).
`pytest` may be used as an optional discovery runner if installed, but all test files are fully
self-contained and compatible with `python -m unittest discover`.

```
tests/
├── test_features.py               # 25 URL feature extractors & boundary inputs
├── test_rules.py                  # Deterministic security rule triggers
├── test_risk_engine.py            # 0-100 composite scoring and level thresholds
├── test_api.py                    # Flask REST API endpoints, payloads, and error codes
├── test_ml_pipeline.py            # Phase 3 – Random Forest URL ML pipeline
├── test_database.py               # Phase 6 – MongoDB + in-memory fallback + privacy
├── test_text_model.py             # Phase 7 – TF-IDF + Logistic Regression text ML pipeline
├── test_url_regression.py         # Phase 8 – URL validation and analysis edge cases
├── test_message_regression.py     # Phase 8 – Message/SMS analysis edge cases
└── test_model_loading_failure.py  # Phase 8 – Graceful degradation when models are absent
```

---

## 2. Test Execution

### Primary command (no third-party tools needed)
```bash
python run_tests.py
```

### Alternative discovery (requires pytest)
```bash
pytest -q
```

### Direct unittest discovery
```bash
python -m unittest discover -v tests
```

---

## 3. Phase 8 Final Test Results

| Phase | Module | Tests | Result |
|-------|--------|-------|--------|
| 1–3 | URL Features | 10 | ✅ PASS |
| 1–3 | Cybersecurity Rules | 5 | ✅ PASS |
| 1–3 | Risk Engine | 4 | ✅ PASS |
| 1–3 | Flask REST API | 9 | ✅ PASS |
| 3 | ML Pipeline (URL Random Forest) | 10 | ✅ PASS |
| 6 | Database & History | 13 | ✅ PASS |
| 7 | Text ML Pipeline | 10 | ✅ PASS |
| 8 | URL Regression | 13 | ✅ PASS |
| 8 | Message Regression | 10 | ✅ PASS |
| 8 | Model Loading Failure | 9 | ✅ PASS |
| **TOTAL** | | **93** | **✅ 93/93 PASS** |

> Pre-Phase-8 baseline: 61 tests. Phase 8 added 32 regression/hardening tests.

---

## 4. Verification of Core Test Cases

| # | Test Case Description | Test Method | Expected Behaviour |
|---|---|---|---|
| 1 | Legitimate URL | `test_legitimate_url_features` | Zero high-severity rules, Low risk, Legitimate verdict |
| 2 | Suspicious URL with IP | `test_analyze_url_suspicious_ip` | Risk > 55, triggers IP indicator |
| 3 | URL with IP address | `test_ip_address_detection` | `has_ip_address=1`, rule `URL_IP` (+22 pts) |
| 4 | URL with `@` symbol | `test_at_symbol_detection` | `has_at_symbol=1`, rule `URL_AT` (+20 pts) |
| 5 | Very long URL | `test_very_long_url` | Rejected with "exceeds" error |
| 6 | URL with multiple subdomains | `test_excessive_subdomains` | Triggers `URL_EXCESSIVE_SUBDOMAINS` |
| 7 | URL with suspicious keywords | `test_suspicious_keywords` | Triggers `URL_KEYWORD_DENSITY` |
| 8 | Empty URL input | `test_analyze_url_empty_validation` | HTTP 400, no server exception |
| 9 | Scheme-less URL (`google.com`) | `test_validate_scheme_less_url` | Normalised to `http://google.com` |
| 10 | `javascript:` scheme | `test_invalid_scheme_rejection` | Rejected: "Unsupported or unsafe protocol" |
| 11 | `data:` scheme | `test_data_scheme_rejection` | Rejected |
| 12 | `file:` scheme | `test_file_scheme_rejection` | Rejected |
| 13 | Normal benign SMS | `test_analyze_message_valid` | Legitimate classification |
| 14 | Phishing-style SMS | `test_analyze_message_valid` | High risk, urgency indicators triggered |
| 15 | SMS with embedded URL | `test_message_with_single_url` | URL extracted, cascade analysis performed |
| 16 | Empty message | `test_empty_message` | `success=False`, "cannot be empty" error |
| 17 | Very long message | `test_long_message` | Processes without exception, all keys present |
| 18 | Unicode message | `test_unicode_message` | No Unicode errors, all keys present |
| 19 | MongoDB unavailable | `test_1_mongodb_offline_detection` | In-memory fallback activated, no 500 errors |
| 20 | URL model missing | `test_url_model_missing_model_loaded_false` | `model_loaded=False`, heuristic fallback |
| 21 | Text model missing | `test_text_model_missing_model_loaded_false` | `model_loaded=False`, `ml_probability=None` |
| 22 | Dangerous scheme with model absent | `test_url_model_missing_dangerous_scheme_still_rejected` | Validation still rejects dangerous scheme |

---

---

## 5. Security Audit (Phase 8 & 9)

| Check | Result |
|-------|--------|
| No `requests`/`urllib.request`/`httpx` used on user URLs | ✅ Confirmed |
| No `subprocess`/`os.system` calls | ✅ Confirmed |
| No `selenium`/`playwright`/`pyautogui` | ✅ Confirmed |
| `.env` in `.gitignore` | ✅ Confirmed |
| `.env.example` contains no real secrets | ✅ Confirmed |
| No hardcoded API keys in source | ✅ Confirmed |
| Dangerous URL schemes rejected before any processing | ✅ Confirmed |
| Frontend never recalculates risk independently | ✅ Confirmed |

---

## 6. Phase 9 Explainable AI Test Suite (`tests/test_explanation.py`)

Added in Phase 9 to validate the explainability engine and backward compatibility:

| Group | Tests | Description |
|---|---|---|
| **A: URL Integration** | 17 | Flask test client calls to `/api/analyze-url`, checking explanation keys, numeric probabilities, rule consistency, bounded scores [0, 100], 25-feature length, HTTPS non-safety disclaimer, and API field preservation. |
| **B: Message Integration** | 10 | Flask test client calls to `/api/analyze-message`, verifying URL evidence only appears when URLs are present, risk contribution totals match, and message model terminology is accurate. |
| **C: Feature Descriptions** | 10 | Unit tests ensuring all 25 features have descriptions, observation levels are valid, and IP/TLD/shortener/HTTPS rules produce correct observations. |
| **D: Explanation Builder** | 7 | Unit tests verifying `build_url_explanation` and `build_message_explanation` return complete dicts with matching risk scores, dynamic timeline stages, and optional global feature importance. |

**Total Phase 9 Tests:** 44  
**Combined Total (Phase 9):** 137 / 137 passing (100% pass rate)

---

## 7. Phase 10 QR / Quishing Detection Test Suite (`tests/test_qr.py`)

Added in Phase 10 to validate the OpenCV QR decoding engine, dangerous scheme interception, static URL pipeline integration, network isolation, and database persistence:

| Group | Tests | Description |
|---|---|---|
| **1. Decoding & Input Validation** | 10 | Validates HTTPS/HTTP/suspicious/plain-text QR decoding, empty bytes, corrupted image bytes, unsupported non-image formats, oversized dimensions, and blank solid images with no QR. |
| **2. Dangerous Scheme Rejection** | 6 | Validates immediate blocking of dangerous payload schemes (`javascript:`, `data:`, `file:`, `vbscript:`, `about:`) with `prediction: "Blocked"` and `risk_score: 100`, plus unit testing of `_is_dangerous_scheme`. |
| **3. Pipeline Integration** | 7 | Verifies that decoded URLs reuse the existing URL Analyzer: 25 features extracted, Random Forest model applied, security rules evaluated, composite risk engine calculated, and Phase 9 explanation dict returned. |
| **4. Database & Persistence** | 2 | Confirms `save_scan` records scans with `input_type="qr"`, retrieval through `get_scan_history(scan_type="qr")`, and in-memory credential/token privacy sanitization. |
| **5. Security & Network Isolation** | 3 | Verifies zero outbound network requests (`requests.get`, `requests.post`, `urllib.request.urlopen` patched and asserted uncalled), zero browser/process launching, and dangerous schemes blocked before URL analysis. |
| **6. REST API Integration** | 3 | Validates `POST /api/analyze-qr` endpoint with valid QR images, missing image payload (HTTP 400), and corrupted file uploads (graceful controlled error). |

**Total Phase 10 Tests:** 31  
**Combined Suite Total (Unified Runner):** 168 / 168 passing (100% pass rate)  
**Pytest Total:** 244 / 244 passing (100% pass rate)

---

## 8. Phase 11 Threat Intelligence Test Suite (`tests/test_threat_intelligence.py`)

Added in Phase 11 to validate external threat intelligence provider normalization, in-memory TTL caching, bounded risk calculation, pipeline enrichment, credential protection, and API contracts:

| Group | Tests | Description |
|---|---|---|
| **1. VirusTotal Provider States** | 13 | Validates unconfigured state, high-malicious (>5 detections), suspicious-only, clean/zero detections, HTTP 404 not-found, HTTP 429 rate-limited, HTTP 401/403 unauthorized, HTTP 500 error, timeout, connection_error, malformed JSON, credential masking, and zero-fetch guarantee. |
| **2. In-Memory Cache** | 5 | Validates cache misses returning `None`, hits returning cached `ThreatIntelResult`, prevention of redundant provider queries on hit, TTL expiry pruning, and URL cache isolation. |
| **3. Service Orchestration & Risk Modifiers** | 5 | Validates singleton lifecycle, default unconfigured fallback values, zero-point guarantee across all non-success/clean states, and bounded point application (+8 and +15). |
| **4. Risk Engine Integration** | 6 | Verifies local score preservation when TI is unconfigured, errored, timed out, or clean; validates bounded point increments; checks [0, 100] score bounds; confirms transparency breakdown fields. |
| **5. Explainable AI Integration** | 2 | Ensures Phase 9 explanation builder incorporates threat intelligence evidence into the investigation timeline and report without crashes when absent. |
| **6. Pipeline & Multi-Modal Integration** | 3 | Confirms URL and Message analyzer integration, local score preservation on TI failure, and propagation of cascaded URL intelligence into message results. |
| **7. Security & Integrity** | 2 | Validates that dangerous schemes are blocked before TI queries, and confirms timeout parameters are passed to network requests. |
| **8. Flask REST API Contracts** | 3 | Validates `POST /api/analyze-url` and `POST /api/analyze-message` include `threat_intelligence` metadata, and confirms secret API keys are never exposed in API responses. |

**Total Phase 11 Tests:** 39  

---

## 9. Phase 12 Screenshot Vision Test Suite (`tests/test_screenshot.py`)

Added in Phase 12 to validate OpenCV contour heuristics, optional OCR graceful degradation, text indicator scanning, brand-domain correlation, risk engine bounding, and REST API contracts:

| Group | Tests | Description |
|---|---|---|
| **1. Image Validation** | 6 | Validates valid JPEG, PNG, WEBP formats, oversized payloads (>10MB), unsupported extensions, and corrupted bytes. |
| **2. Visual Structure** | 3 | Validates blank images, synthetic login forms with multiple contours, and strictly bounds visual points at 35. |
| **3. OCR Graceful Degradation** | 3 | Verifies mock text extraction, graceful fallback when Tesseract is missing, and exception safety. |
| **4. Text Indicators** | 5 | Validates extraction of credential, urgency, financial, and brand keywords, plus benign text. |
| **5. URL & Domain Extraction** | 3 | Validates extraction of full URLs, bare domains, and text with no URLs. |
| **6. Brand-Domain Correlation** | 3 | Validates brand-domain consistency, mismatch detection (+20 pts), and empty cases. |
| **7. Risk Engine Bounding** | 4 | Verifies all-zero baseline, individual component caps, high threshold verdict, and partial scores. |
| **8. Explanation Structure** | 2 | Ensures Phase 9 explanation builder incorporates visual and OCR evidence with dynamic timelines. |
| **9. Pipeline Orchestration** | 2 | End-to-end testing with clean images and mocked OCR + URL cascades. |
| **10. Security Guarantees** | 2 | Verifies zero outbound network requests and ephemeral in-memory processing (never saved to disk). |
| **11. REST API Contract** | 6 | Validates `/api/analyze-screenshot` endpoint, missing fields, empty filenames, disallowed formats, and persistence. |

**Total Phase 12 Tests:** 39  

---

## 10. Phase 13 Email (.EML) Analysis Test Suite (`tests/test_email.py`)

Added in Phase 13 to validate Python standard-library RFC 5322 MIME parsing, header integrity, Authentication-Results verification (SPF, DKIM, DMARC), subject social-engineering triggers, safe body text extraction, URL cascades, and attachment metadata analysis:

| Group | Tests | Description |
|---|---|---|
| **1. File Validation** | 5 | Validates valid .eml, empty bytes, oversized payloads (>10MB), non-.eml extension rejection, and malformed non-email files. |
| **2. Email Parsing** | 5 | Validates plain-text, multipart (plain + HTML), encoded RFC 2047 subjects, missing headers, and multiple recipients. |
| **3. Header Forensics** | 5 | Validates Reply-To domain mismatch, matching Reply-To, Return-Path divergence, missing Date/Message-ID, and multiple '@' signs in sender. |
| **4. Authentication Forensics** | 4 | Validates SPF/DKIM/DMARC pass (0 pts), DMARC failure (+10 pts), SPF softfail (+4 pts), and absent Authentication-Results header. |
| **5. Subject Social Engineering** | 5 | Validates urgency triggers, account suspension alerts, credential verification requests, financial demands, and benign subjects. |
| **6. Body Analysis & NLP Proxy** | 2 | Validates safe text extraction from HTML without script execution, and body evaluation through the TF-IDF + Logistic Regression proxy. |
| **7. URL Extraction & Cascades** | 2 | Validates plain-text and HTML href URL extraction, deduplication, and cascading of the highest-risk link (not summed). |
| **8. Attachment Forensics** | 5 | Validates benign PDFs, executable extensions (.exe), double extensions (e.g. `statement.pdf.exe`), path traversal in filenames (`../../`), scripts (.vbs), and macros (.docm). |
| **9. Security & HTML Safeguards** | 5 | Validates active `<script>` tag detection, `<iframe>` injection, `javascript:` links, inline event handlers (`onclick`), and asserts zero outbound network calls to extracted URLs. |
| **10. Risk Engine Point Allocations** | 3 | Validates all-zero baseline, individual component capping (Header ≤20, Auth ≤20, Subject ≤15, Body ≤30, Attachment ≤15, URL ≤20), clamping of raw sums (120 pts) to [0, 100], and partial scores. |
| **11. Explanation & Dynamic Timeline** | 1 | Validates that Phase 9 explanation builder generates all evidence blocks, domain breakdown, and dynamic timeline stages. |
| **12. Database Persistence** | 1 | Validates that `save_scan` correctly records email scans with `input_type="email"` and sanitized metadata. |
| **13. REST API Contract** | 5 | Validates `POST /api/analyze-email` endpoint with valid .eml, missing form field, empty filename, disallowed extension, and corrupt file. |

**Total Phase 13 Tests:** 48  
**Combined Suite Total (Unified Runner `run_tests.py`):** 294 / 294 passing (100% pass rate)  
**Pytest Total (`pytest -q`):** 370 / 370 passing (100% pass rate)

---

## 11. Known Testing Limitations

- **sklearn version mismatch** (model saved with 1.9.1, loaded under 1.8.0): Produces `InconsistentVersionWarning` (non-fatal). Models still load and produce valid predictions.
- **Whitespace-only message** is processed rather than rejected (`success=True`). This is documented in `test_whitespace_only_message` as a known limitation.
- **MongoDB not running locally**: all database tests use the in-memory fallback. Tests that mock MongoDB online still pass via `unittest.mock`.
- **No live HTTP requests** are made during any test — this is by design (SSRF safety and offline test reproducibility).
- **Single QR Code per Image**: Multi-QR decoding is intentionally scoped to single-QR reliability to avoid inaccurate risk aggregation formulas.
- **Passive Authentication Only**: SPF/DKIM/DMARC tests validate parsing of the `Authentication-Results` header; no live DNS queries are simulated or required.


