# PhishGuard AI - System Limitations

A core requirement of an honest academic PBL engineering project is explicit acknowledgement of theoretical and practical operational boundaries.

---

## 1. Fundamental Detection Boundaries

### 1.1 No Model Is 100% Accurate
No machine learning classifier or cybersecurity heuristic can guarantee 100% detection accuracy. Claims of perfect detection are scientifically fraudulent. Adversarial attackers constantly evolve tactics to reside just beneath statistical detection thresholds.

### 1.2 Zero-Day & Fast-Flux Infrastructure
Phishing sites frequently register brand-new domains, spin up disposable VPS instances, conduct campaigns for 4 to 6 hours, and tear down DNS records before security vendors can label the threat. Static lexical models that rely solely on known TLDs or keyword density may fail to catch zero-day campaigns using benign-looking alphanumeric tokens.

### 1.3 False Positives & Legitimate Edge Cases
- **Legitimate Complex URLs:** Modern cloud portals (AWS CloudWatch console, Microsoft Azure SSO, Google Workspace authentication) feature long URLs, multiple nested subdomains, and extensive tracking parameters. These can occasionally trigger low or medium severity rules (false alarms).
- **Legitimate Shortened Links:** Legitimate newsletters and social media feeds frequently use `bit.ly` or `t.co` link shorteners. Flagging them as suspicious represents a necessary trade-off for caution.

### 1.4 False Negatives & Adversarial Evasion
- **Reverse Proxy Man-in-the-Middle (Evilginx / Modlishka):** Advanced attackers proxy genuine corporate login pages through their own domain names, intercepting session cookies and bypassing MFA. If the proxy domain name mimics a standard business name, lexical analysis alone cannot verify site authenticity without DNS/certificate pinning.
- **Homoglyph & Punycode Attacks:** Attackers use Cyrillic or Greek characters visually indistinguishable from Latin characters (e.g. `pаypal.com` with Cyrillic 'а'). While character set normalization helps, sophisticated homoglyphs can evade filters.

---

## 2. Technical & Architectural Boundaries

### 2.1 Absence of Live Network Crawling (SSRF Guard)
PhishGuard AI purposefully avoids performing live HTTP GET/POST requests or headless browser rendering of target URLs. 
- **Benefit:** Protects the host server against Server-Side Request Forgery (SSRF), internal network scanning, and zero-day drive-by malware execution.
- **Trade-off:** The system cannot inspect dynamic client-side JavaScript payloads, canvas fingerprinting scripts, or HTTP 302 redirect chains.

### 2.2 HTTPS Misconception
Over 85% of malicious websites now utilize valid SSL/TLS certificates provided by automated free certificate authorities (e.g. Let's Encrypt). The presence of HTTPS indicates encrypted transport, **not** organizational trustworthiness or benign intent.

### 2.3 Screenshot Vision Inspection Limitations
Multimodal vision analysis models (Google Gemini / OpenAI Vision) are probabilistic pattern evaluators. Poor image resolution, partial cropping, or dark mode styling can cause the vision model to misidentify corporate logos or overlook credential input dialogs.

### 2.4 LLM Explanation Non-Authoritativeness
Natural Language explanations provided by LLMs are intended strictly for educational accessibility. LLMs may occasionally produce conversational imprecision. Therefore, PhishGuard AI enforces an architectural boundary: **LLMs never classify URLs and never alter the numerical risk score**.

---

## 3. Operational Guidance: Decision-Support Philosophy
PhishGuard AI must be treated as a **decision-support tool** for end users and SOC junior analysts. It synthesizes signals to augment human judgment, not as absolute legal or operational proof of malicious intent.

---

## 4. ML Model Probability Interpretation (Phase 4)

### 4.1 ML Probability Is an Estimate
The Random Forest's `predict_proba()` output represents the **proportion of trees in the ensemble** that voted for the phishing class. It is a statistical posterior estimate based on the training distribution — not a definitive certainty.

### 4.2 Risk Score Is Project-Defined
The composite Risk Score (0–100) is computed using a weighted formula specific to PhishGuard AI:
```
Risk Score = min(100, ML_Base(60%) + Rule_Impact(40%))
```
The tier boundaries (Low: 0–24, Medium: 25–54, High: 55–79, Critical: 80–100) are **project-defined thresholds**, not ISO/NIST standards. They should not be cited as universal cybersecurity benchmarks.

### 4.3 Feature-Based Analysis Is Static
All 25 features are extracted from the URL **string** alone:
- No DNS resolution is performed.
- No WHOIS lookups are performed.
- No HTTP response is fetched.
- No certificate validity is checked.

This is an intentional SSRF safety design. It means that a URL pointing to a legitimate server but structurally resembling a phishing URL could receive a high risk score.

### 4.4 Suspicious TLD ≠ Proven Phishing
Many TLDs historically correlated with phishing abuse (`.tk`, `.ml`, `.xyz`, `.top`) are also used by legitimate websites, personal projects, and academic research pages. A suspicious TLD flag is a risk signal, not proof of malicious intent.

### 4.5 HTTPS Does Not Guarantee Legitimacy
The `uses_https` feature contributes significantly to the model's Gini importance (41.88%). However, this does not mean HTTP sites are definitively phishing. It reflects that phishing sites in the training corpus more frequently used plain HTTP. Many legitimate staging servers, internal tools, and older platforms use HTTP.

### 4.6 sklearn Version Warning
The trained model was saved with scikit-learn 1.8.0. When loaded under scikit-learn 1.9.1+, an `InconsistentVersionWarning` is raised. This is a non-fatal warning; the model loads and produces valid predictions. For production deployments, the model should be retrained or re-serialized under the target runtime version.

---

## 5. Database, History & Telemetry Limitations (Phase 6)

### 5.1 MongoDB Daemon is Optional for Local Operation
The application integrates an automatic in-memory ring-buffer fallback. If MongoDB is not running locally (e.g. on student presentation machines), the application operates without errors, but records in the fallback memory will clear upon server shutdown or restart.

### 5.2 Dashboard Accuracy Depends on Stored Scans
Dashboard metric counters, classification distributions, and timeline plots reflect strictly the scans stored in the database. When starting with a fresh database or cleared memory, the dashboard displays a genuine zero state. PhishGuard AI never seeds fabricated numbers.

### 5.3 Potential Sensitivity of User-Submitted Content
While the built-in privacy layer automatically scrubs passwords, API keys, OTPs, and payment card numbers from stored records, user-submitted URLs and messages may still contain identifying domain names or correspondence context. In sensitive enterprise environments, `STORE_RAW_CONTENT=false` should be enabled in `.env`.

### 5.4 Production Security & Data Retention Policies
For production deployments:
- MongoDB must be secured with authentication, role-based access control (RBAC), and encrypted TLS connections (`mongodb+srv://`).
- Time-to-Live (TTL) indexes or scheduled pruning jobs should be instituted to automatically expire historical logs older than standard compliance retention periods (e.g., 90 days).

---

## 6. Phase 8 Security Hardening Findings

### 6.1 No Network Requests on User-Provided Input (Verified)
A static analysis was performed across `services/url_analyzer.py`, `services/message_analyzer.py`,
and all route handlers. The following network-fetching libraries are **not** imported or invoked
anywhere in the analysis pipeline:

- `requests`, `httpx`, `aiohttp`, `urllib.request`
- `subprocess`, `os.system`
- `webbrowser`, `selenium`, `playwright`, `pyautogui`

Only safe standard-library modules are used: `urllib.parse`, `re`, `json`, `logging`.

### 6.2 Dangerous URL Scheme Rejection
The following URL schemes are explicitly rejected by `validate_and_normalize_url` before any
feature extraction or model inference occurs:

`javascript:`, `data:`, `file:`, `vbscript:`, `about:`

This protection operates independently of whether the ML model is loaded.

### 6.3 Environment Secret Security
- `.env` is listed in `.gitignore` and will not be committed to version control.
- `.env.example` contains only placeholder variable names with no real secrets.
- No API keys, database credentials, or authentication tokens are hardcoded in any source file.

### 6.4 Whitespace-Only Message Input (Known Minor Limitation)
The message analyzer strips leading/trailing whitespace but does **not** reject whitespace-only
input as invalid. Such input is processed as a near-empty message with a near-zero risk score
and `success=True`. This is a known limitation documented in `test_whitespace_only_message`.
Future phases may add strict whitespace validation.

### 6.5 sklearn Version Warning (Non-Fatal)
Models were trained and serialised with scikit-learn 1.9.1. The runtime environment has
scikit-learn 1.8.0, causing `InconsistentVersionWarning` on model load. This is **non-fatal**;
predictions are still produced. For production, retrain and re-serialise under the target version.

---

## 7. Phase 9 Explainability Boundaries

### 7.1 Scope of Current Explainability
- **No Per-Sample Attribution (No SHAP / LIME):** PhishGuard AI does not currently implement per-sample attribution libraries (such as SHAP or LIME) due to performance overhead and dependency footprint. Explanations decompose the prediction into observable structural metrics, deterministic rule contributions, and global feature importance.
- **Global Feature Importance Is Dataset-Level:** The `GLOBAL MODEL FEATURE IMPORTANCE` section reflects the Random Forest's overall feature importance across all training samples. It does not measure the marginal contribution of an individual feature for any specific analyzed URL.
- **Observation vs. Causality:** Feature descriptions reflect structural properties (e.g. *"An IP address was detected"*), not proof of malice or causal attribution for the classification.
- **Text Classifier Domain Semantics:** The text classification model is trained on the UCI SMS Spam Collection. It classifies messages for **spam and malicious solicitation patterns**; it is not a dedicated phishing classifier. Phishing risk is determined through composite scoring that blends text classification with heuristic indicators and embedded URL cascades.
- **Out of Scope for Phase 9:** QR detection (quishing), external threat intelligence APIs, screenshot vision analysis, and email header analysis are explicitly out of scope and deferred to subsequent phases.

---

## 8. Phase 10 QR / Quishing Detection Limitations

### 8.1 Single QR Code per Image
The QR decoding subsystem leverages OpenCV `cv2.QRCodeDetector` with multi-scale fallback. While robust for standard single-code images (posters, decals, emails, bills), it focuses on the primary QR code in the frame. Complex images with multiple interspersed QR codes are not aggregated under a multi-code heuristic to prevent flawed composite risk assumptions.

### 8.2 No Separate QR ML Model
There is **no standalone QR machine learning model**. QR decoding functions strictly as an input extraction modality. All phishing intelligence, lexical evaluation, Random Forest inference, rule evaluations, and Phase 9 explanations are executed by the existing URL analysis pipeline.

### 8.3 Physical Distortions and Extreme Angles
Heavily torn, severe glare reflections, motion-blurred, or extreme perspective angles (> 60° off-axis) may prevent OpenCV's finder-pattern recognition from identifying the timing and alignment patterns.

### 8.4 Plain Text and Non-URL Payloads
QR codes containing non-URL text (vCards, plain contact information, crypto wallet strings, Wi-Fi configuration keys) are safely classified as `payload_type: "text"` with `prediction: "Informational"` and `risk_score: 0`. PhishGuard AI does not fabricate URL risk or phishing scores for arbitrary non-URL text strings.

### 8.5 Ephemeral Image Processing
Uploaded QR images are strictly decoded in RAM using Pillow and OpenCV before being discarded. No uploaded images are permanently written to disk or stored in MongoDB, preserving user visual privacy and preventing storage exhaustion.

---

## 9. Phase 11 Threat Intelligence Boundaries

### 9.1 Enrichment Only — Never Overrides Local Consensus
External Threat Intelligence (VirusTotal) serves strictly as an **optional corroboration and enrichment layer**. The primary line of defense remains PhishGuard AI's local Random Forest classifier and deterministic heuristic rules. Unconfigured, failed, unreachable, or rate-limited external providers contribute exactly **0 risk points** and never degrade local analysis.

### 9.2 Rate Limits & Quota Exhaustion
The free/public tier of VirusTotal enforces strict request thresholds (e.g., 4 requests/minute, 500 requests/day). PhishGuard AI implements an in-memory thread-safe TTL cache (default 3600 seconds) to mitigate repeat lookups, but high-throughput analysis will gracefully encounter `rate_limited` statuses. The application treats rate limits as non-fatal events, maintaining continuous local operation.

### 9.3 Zero-Day Lag in Threat Repositories
External threat intelligence feeds rely on telemetry reported after attacks have launched and been analyzed by security vendors. Brand new zero-day domains, short-lived campaigns (lasting under 4 hours), or targeted spear-phishing links will often appear as `not_found` or 0 detections in external databases. This reinforces why local statistical and lexical ML analysis is essential.

### 9.4 Zero-Fetch Guarantee (Passive Intelligence)
PhishGuard AI never contacts, crawls, or fetches submitted target URLs during threat intelligence lookups. Provider queries use URL-safe base64 identifiers transmitted strictly over HTTPS to official API endpoints. Live payload execution, certificate verification, and DOM analysis are outside the scope of passive threat intelligence.

### 9.5 Credential Masking & Privacy
API keys are loaded via environment variables and masked from all user-facing interfaces, logs, API JSON responses, and MongoDB records. Raw vendor breakdown dictionaries with individual antivirus names are filtered out to keep response payloads lightweight, vendor-agnostic, and secure.

---

## 10. Phase 12 Screenshot / Visual Phishing Detection Limitations

### 10.1 Heuristic Visual Processing vs. Deep Learning Models
Phase 12 relies intentionally on **lightweight, explainable OpenCV contour detection** and geometrical aspect ratio analysis. It identifies structural features common to credential harvesting pages (multiple input-like rectangles, submit buttons, form grouping, layout clutter). It does **not** employ multi-gigabyte convolutional neural networks (CNNs) or vision transformers. Consequently, modern, non-traditional login layouts (e.g. multi-step dialogs with only a single field visible at a time) or stylized canvas elements may not match traditional form box heuristics.

### 10.2 Decoupled, Optional Optical Character Recognition (OCR)
The text extraction pipeline utilizes an optional wrapper around `pytesseract`. If Tesseract OCR binaries are not present on the host environment (such as minimal student or container setups), the system enters a controlled `ocr_available: false` state and continues executing OpenCV structural heuristics with zero crash. However, in this offline state, text-based indicator scoring (credentials, urgency, banking keywords) and OCR-based domain extraction are disabled.

### 10.3 Static Brand Correlation Dictionary
Brand-domain mismatch detection evaluates a static dictionary of high-risk impersonated targets (e.g. PayPal, Microsoft, Google, Apple, Amazon). While effective against frequent consumer credential phishing, it does not exhaustively represent all regional institutions, corporate intranets, or private web apps.

### 10.4 Zero Outbound Target Browsing Guarantee
Extracted URLs and bare domains are never visited, rendered, or fetched via headless browsers. This architectural principle guarantees absolute protection against SSRF, tracking beacons, and drive-by malware execution. PhishGuard AI analyzes the lexical and structural properties of extracted URLs through the existing Phase 8 URL Analyzer, but cannot verify the live server's rendered DOM content.

### 10.5 Ephemeral In-Memory Image Lifecycle
Uploaded screenshot bytes are processed strictly in RAM (`io.BytesIO`) and discarded immediately upon completion of feature extraction. Raw images are never saved to disk or persistent storage databases. Only extracted features, visual counts, and risk scores are persisted.

---

## 11. Phase 13 Email Phishing Analysis (.EML) Limitations

### 11.1 Passive Authentication Forensics vs. Active DNS Queries
Verification of SPF, DKIM, and DMARC is performed strictly by parsing the `Authentication-Results` header recorded by receiving mail transfer agents (MTAs) within the uploaded `.eml` file. PhishGuard AI does **not** perform active live DNS queries, public key cryptography verification on DKIM signatures, or evaluate live DMARC policy records over the network. If the incoming MTA did not prepend an `Authentication-Results` header or if the header was omitted, authentication verdicts are marked `not_present` and contribute 0 risk points.

### 11.2 Reused Text Classifier as Body Proxy (Not Email-Specific Model)
Body text analysis reuses the Phase 7 TF-IDF + Logistic Regression classifier (trained on the UCI SMS Spam Collection) strictly as a linguistic proxy signal for social-engineering manipulation. PhishGuard AI does **not** claim to have trained an email-specific ML model in Phase 13, and no fabricated email accuracy metrics are asserted.

### 11.3 Attachment Metadata Forensics vs. Sandbox Detonation
Attachment inspection is strictly limited to static file metadata: filename syntax, extension categories (executables, scripts, macro-enabled formats, archives), double extensions (e.g. `invoice.pdf.exe`), MIME content types, and path traversal strings (`../`). PhishGuard AI does **not** execute, unpack, or detonate attachments in an active sandbox environment, ensuring complete security against drive-by exploits.

### 11.4 Lexical URL Cascade without Server Rendering
URLs extracted from email plain-text and HTML anchors are cascaded directly through the static 25-feature Random Forest URL Analyzer and optional VirusTotal Threat Intelligence. The system never establishes network connections to destination web servers or renders remote pages, eliminating tracking beacon execution, SSRF vulnerabilities, and client compromise.

### 11.5 Ephemeral In-Memory File Lifecycle & Privacy Guarantees
Uploaded `.eml` files are parsed entirely in memory via Python's standard library and discarded immediately after feature extraction. Raw `.eml` files, entire email bodies, and recipient lists are **never** persisted to the MongoDB audit database or logged to application logs. Database records store only sanitized sender domains, truncated subject snippets, feature counts, and computed risk breakdowns.
