# PhishGuard AI — Phase 13 Implementation Report
## Email Phishing Analysis (.EML) & Multi-Domain Forensic Investigation

**Date:** October 1, 2026  
**System:** PhishGuard AI — Explainable AI-Based Multi-Modal Phishing Detection System  
**Phase:** 13 (Email Phishing Analysis — .EML)  
**Status:** COMPLETE & FULLY VERIFIED  

---

## 1. Executive Summary

Phase 13 introduces **Email Phishing Analysis (.EML)** as a core input modality in PhishGuard AI. Users can submit standard RFC 5322 email files (`.eml`) through an interactive drag-and-drop web interface or via the REST API endpoint `POST /api/analyze-email`.

The email analysis pipeline operates entirely in-memory using Python's standard-library email facilities. It investigates six distinct evidence domains:
1. **Header Forensics:** Evaluates sender domain consistency, Reply-To mismatches, Return-Path divergences, and delivery header completeness (≤ 20 risk points).
2. **Authentication Header Verification:** Parses SPF, DKIM, and DMARC verdicts directly from incoming `Authentication-Results` headers (≤ 20 risk points).
3. **Subject Social Engineering:** Detects psychological urgency, credential demands, account suspension alerts, and financial pressure patterns (≤ 15 risk points).
4. **Body Linguistic Inspection:** Strips HTML safely, detects embedded scripts, and reuses the trained TF-IDF + Logistic Regression model as an explainable message proxy signal (≤ 30 risk points).
5. **Attachment Metadata Forensics:** Screens filenames, double extensions (e.g. `invoice.pdf.exe`), path traversal strings, executable formats, scripts, and macros without binary execution (≤ 15 risk points).
6. **Embedded URL Cascading:** Deduplicates hyperlinks, passes each through the existing Random Forest URL Analyzer and optional VirusTotal Threat Intelligence, and scales the highest URL risk into the composite score (≤ 20 risk points).

All risk allocations are **risk points** (not percentages), totaling 120 raw points, normalized and strictly clamped to a final index of `[0, 100]`.

---

## 2. Architecture & Processing Flow

```
Raw .EML Upload (Max 10 MB)
         │
         ▼
[Secure EML Validator] ── Rejects empty, corrupted, oversized (>10MB), or non-.eml files
         │
         ▼
[BytesParser (email.policy.default)] ── Decodes RFC 5322 MIME structures in RAM
         │
         ├──► [Header Forensics] ───────────────► Reply-To Mismatch, Return-Path Divergence (≤20 pts)
         ├──► [Authentication Forensics] ──────► SPF, DKIM, DMARC statuses from header (≤20 pts)
         ├──► [Subject Line Analyzer] ──────────► Urgency, Credential, Financial triggers (≤15 pts)
         ├──► [Safe HTML Parser] ───────────────► Neutralizes <script>, <iframe>; extracts text & hrefs
         ├──► [Body Text NLP Proxy] ────────────► TF-IDF + Logistic Regression proxy signal (≤30 pts)
         ├──► [URL Cascade Engine] ─────────────► Highest-risk link cascaded via URL Analyzer (≤20 pts)
         └──► [Attachment Forensics] ───────────► Extension, double extension, path traversal (≤15 pts)
         │
         ▼
[Centralized Risk Engine (calculate_email_risk)]
         │ Clamped Formula: min(100, Header + Auth + Subject + Body + Attachment + URL_Cascade)
         ▼
[Phase 9 Explanation Builder (build_email_explanation)]
         │ Structured evidence report, domain breakdowns, dynamic chronological timeline
         ▼
[REST Response (200 OK) & Ephemeral MongoDB Persistence]
```

---

## 3. Evidence Domain Breakdown & Bounded Point Allocation

Risk points are allocated according to the verified implementation:

| Evidence Domain | Max Point Allocation | Key Indicators Evaluated |
|---|---|---|
| **Header Forensics** | Up to 20 pts | Reply-To domain mismatch (+10 pts), Return-Path divergence (+5 pts), Multiple '@' symbols (+7 pts), Display name email spoofing (+5 pts), Missing Date (+3 pts), Missing Message-ID (+3 pts). |
| **Authentication Forensics** | Up to 20 pts | DMARC failure (+10 pts), SPF failure (+7 pts), DKIM failure (+7 pts), SPF softfail (+4 pts). Pass verdicts contribute 0 pts. |
| **Subject Analysis** | Up to 15 pts | Urgent time pressure (+5 pts), Account suspension alert (+5 pts), Credential verification request (+5 pts), Financial/billing demand (+4 pts), Empty subject (+2 pts). |
| **Body NLP Proxy** | Up to 30 pts | Statistical posterior probability from TF-IDF + Logistic Regression model ($round(P \times 30)$ pts), supported by heuristic keyword patterns. |
| **Attachment Forensics** | Up to 15 pts | Executable extensions (.exe, .scr, .bat) (+12 pts), Double extensions (+12 pts), Script extensions (.js, .vbs, .ps1) (+10 pts), Path traversal characters (+10 pts), Macro-enabled documents (.docm, .xlsm) (+7 pts), Compressed archives (.zip) (+3 pts). |
| **URL Cascade** | Up to 20 pts | Scaled from the highest URL risk score detected in the email: $min(round(max\_url\_risk \times 0.20), 20)$ pts. |
| **Total Allocation** | **120 pts** | **Final Score Clamped to [0, 100]:** $min(100, max(0, \sum Points))$ |

---

## 4. Academic Transparency & Disclaimers

In compliance with academic PBL integrity standards:
1. **Body NLP Model Reused as Proxy:** The text classifier is the TF-IDF + Logistic Regression model trained on the UCI SMS Spam Collection. It is **not** an email-specific trained classifier. It is utilized strictly as an explainable proxy signal for linguistic social-engineering markers.
2. **Passive Header Verification:** SPF, DKIM, and DMARC results are read directly from the `Authentication-Results` header inserted by upstream mail servers. The system does not perform active DNS queries.
3. **No Dynamic Sandbox Execution:** Attachments are evaluated strictly via static filename and extension metadata.
4. **Multiple URL Aggregation:** Multiple URLs are not summed into an unbounded score; the highest-risk URL provides the scaled cascade contribution.

---

## 5. Security & Privacy Safeguards

- **Zero Remote HTTP Requests:** Extracted URLs are evaluated lexically; the server never connects to destination hosts.
- **HTML Script Neutralization:** Email HTML bodies are parsed with Python's standard library `html.parser.HTMLParser`. Embedded `<script>`, `<iframe>`, `javascript:` URIs, and inline `on*` event handlers are detected, flagged as critical security anomalies, and excluded from text rendering.
- **Zero Attachment Execution:** Attachment payloads are never opened, executed, or imported.
- **Ephemeral In-Memory Lifecycle:** Uploaded `.eml` files are parsed in RAM and discarded immediately. Raw `.eml` files, complete email bodies, and recipient lists are never written to disk or stored in the database.
- **Threat Intelligence Boundaries:** Only extracted URLs are looked up in VirusTotal; email headers, subjects, bodies, and attachments are strictly withheld from external transmission.

---

## 6. Verification & Test Metrics

### Test Suite Execution Summary

| Metric | Verified Baseline | Phase 13 Final | Net Change |
|---|---|---|---|
| **pytest (`python -m pytest -q`)** | 322 passed, 0 failed, 13 warnings | **370 passed, 0 failed, 13 warnings** | **+48 tests** |
| **Unified Runner (`python run_tests.py`)** | 246 passed, 0 failed | **294 passed, 0 failed** | **+48 tests** |
| **Pass Rate** | 100% | **100%** | Zero regressions |
| **Test Execution Time** | ~3m 14s | **~3m 23s** | Stable performance |

### Phase 13 Test Groups (`tests/test_email.py` - 48 Tests)
1. **File Validation (5 tests):** Valid .eml, empty bytes (0 bytes), oversized file (>10MB), non-.eml extension rejection, malformed non-email bytes.
2. **Email Parsing (5 tests):** Plain text, multipart (plain + HTML), encoded RFC 2047 subjects, missing header tolerance, multiple recipients.
3. **Header Forensics (5 tests):** Reply-To mismatch, Reply-To match, Return-Path divergence, missing Date/Message-ID, multiple '@' in sender.
4. **Authentication (4 tests):** All pass (0 pts), DMARC failure (+10 pts), SPF softfail (+4 pts), absent Authentication-Results header.
5. **Subject Social Engineering (5 tests):** Urgency, suspension, credential verification, financial demands, benign subject.
6. **Body Analysis & NLP Proxy (2 tests):** HTML tag stripping without script execution, TF-IDF + Logistic Regression proxy evaluation.
7. **URL Extraction & Cascades (2 tests):** Plain/HTML extraction and deduplication, multiple URLs cascading highest risk only.
8. **Attachment Forensics (5 tests):** Benign PDF, executable (.exe), double extension (`.pdf.exe`), path traversal (`../../`), scripts and macros.
9. **Security Safeguards (5 tests):** `<script>` tag detection, `<iframe>` injection, `javascript:` link flagging, inline event handlers, zero outbound network assertion.
10. **Risk Engine Point Allocations (3 tests):** All-zero baseline, individual component capping, clamping raw sum (120 pts) to [0, 100], partial scoring.
11. **Explanation & Timeline (1 test):** Generation of all 9 Phase 9 explanation fields and dynamic investigation timeline stages.
12. **Database Persistence (1 test):** `save_scan` with `input_type="email"` and privacy-sanitized metadata.
13. **REST API Contract (5 tests):** `POST /api/analyze-email` success (200), missing file field (400), empty filename (400), disallowed extension (400), corrupt file (400).

---

## 7. Manual Smoke Tests Summary

All 8 requested manual smoke test scenarios were executed and verified:

| Case | Scenario | Tested Attributes | Observed Output | Verdict |
|---|---|---|---|---|
| **Case 1** | Normal legitimate email | Standard headers, benign subject and body | Score = 11, Level = Low, Prediction = Legitimate | PASS |
| **Case 2** | Email with Reply-To mismatch | `From: chase.com`, `Reply-To: phishnet.org` | Flagged `HDR_REPLYTO_MISMATCH` | PASS |
| **Case 3** | Email with authentication failures | `spf=fail`, `dkim=fail`, `dmarc=fail` | Flagged `AUTH_DMARC_FAIL`, `AUTH_SPF_FAIL`, `AUTH_DKIM_FAIL` | PASS |
| **Case 4** | Email with suspicious URL | Embedded link to private IP address | URL extracted and cascaded through URL Analyzer | PASS |
| **Case 5** | Email with multiple URLs | One safe URL + one high-risk URL | Max URL risk applied to cascade; points not summed | PASS |
| **Case 6** | Suspicious attachment metadata | Attachment named `update.exe` | Flagged `ATT_EXECUTABLE` | PASS |
| **Case 7** | HTML email with script payloads | `<script>alert(1)</script>`, `javascript:` URI | Flagged `SCRIPT_TAG_INJECTION`, `JAVASCRIPT_URI`, scripts not executed | PASS |
| **Case 8** | Malformed .eml | Arbitrary non-email text | Caught `ValueError` gracefully, rejected with 400 | PASS |

---

## 8. Files Created and Modified

### Files Created:
1. `services/email_service.py` — Complete .eml parsing, header forensics, auth inspection, URL extraction, attachment analysis, and pipeline orchestrator.
2. `templates/email_analyzer.html` — Retro-modern editorial UI for .eml upload, sender forensics, authentication badges, URL cards, attachment cards, and Phase 9 explainability blocks.
3. `static/js/email_analyzer.js` — Client interaction, dropzone, validation, FormData submission, and result rendering (zero frontend scoring logic).
4. `tests/test_email.py` — 48 automated unit and integration tests.
5. `docs/security.md` — Security architecture, multi-modal threat modeling, and defensive controls.
6. `docs/privacy.md` — Privacy by design, sanitization rules, and external data minimization.
7. `docs/phase13_report.md` — Comprehensive Phase 13 implementation report.

### Files Modified:
1. `services/risk_engine.py` — Appended `calculate_email_risk` with 6 bounded point allocations and clamping to [0, 100].
2. `services/explanation_builder.py` — Appended `build_email_explanation` with structured report, domain breakdowns, and dynamic investigation timeline.
3. `routes/message_routes.py` — Added `POST /api/analyze-email` endpoint.
4. `app.py` — Added `GET /email-analyzer` page view route.
5. `templates/base.html` — Added navigation links for Screenshot Vision and Email (.EML) Analyzer.
6. `database/privacy.py` — Added `sanitize_email_for_storage()` and email support in `sanitize_scan_input()`.
7. `database/mongodb.py` — Added email indicator extraction and metadata handling in `save_scan()`.
8. `run_tests.py` — Registered `test_email` under the unified test runner.
9. `README.md` — Updated feature list (Mode E), technology stack, and architecture diagram.
10. `docs/api_documentation.md` — Documented `POST /api/analyze-screenshot` and `POST /api/analyze-email`.
11. `docs/architecture.md` — Added Phase 13 email pipeline architecture and updated implementation status.
12. `docs/testing.md` — Added Phase 12 and Phase 13 test metrics and updated suite counts.
13. `docs/limitations.md` — Appended Section 11 detailing Phase 13 operational limitations.
