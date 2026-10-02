# PhishGuard AI - System Architecture

## 1. System Overview
**PhishGuard AI** is an explainable multi-modal phishing detection system developed for Academic Programming-Based Learning (PBL) in Bachelor of Engineering (Information Technology). It provides a unified cybersecurity analysis pipeline capable of inspecting:
- Web Uniform Resource Locators (URLs)
- Electronic Mail and Short Message Service (SMS / Smishing) content
- Quick Response (QR) code imagery (Quishing)
- Optional visual screenshots of login interfaces

The architecture strictly separates statistical Machine Learning inference from deterministic heuristic indicators, culminating in a transparent 0–100 composite Risk Score.

---

## 2. Layered Architecture

```
+-------------------------------------------------------------------------+
|                         PRESENTATION LAYER                              |
|   HTML5  *  CSS3 (Dark Cybersecurity Theme)  *  Vanilla JS  *  Chart.js |
|   Pages: Dashboard, URL Analyzer, Message Analyzer, QR, Vision, History |
+-------------------------------------------------------------------------+
                                    | (REST HTTP / JSON)
                                    v
+-------------------------------------------------------------------------+
|                         APPLICATION LAYER (Flask)                       |
|   app.py (App Factory)  *  Blueprints (/api/url, /api/message, ...)     |
|   Security Middleware: Input Sanitization, Max Body Limits, SSRF Guards |
+-------------------------------------------------------------------------+
       |                           |                          |
       v                           v                          v
+----------------+      +---------------------+      +--------------------+
|  URL PIPELINE  |      |   MESSAGE PIPELINE  |      | MULTIMODAL INGEST  |
| 25-Feature Ext |      | Regex Heuristics    |      | pyzbar QR Decoder  |
| RandomForest   |      | TF-IDF Vectorizer   |      | Multimodal Vision  |
| Rule Engine    |      | Logistic Regression |      | (Optional Gemini)  |
+----------------+      +---------------------+      +--------------------+
       |                           |                          |
       +---------------------------+--------------------------+
                                   |
                                   v
+-------------------------------------------------------------------------+
|                       EXPLAINABILITY & RISK ENGINE                      |
|   Formula: Min(100, (ML_Prob * 60) + Min(Rule_Sum, 40))                 |
|   Categorical Risk Tier: Low / Medium / High / Critical                 |
|   Optional LLM Natural Language Translation                             |
+-------------------------------------------------------------------------+
                                   |
                                   v
+-------------------------------------------------------------------------+
|                         PERSISTENCE LAYER                               |
|   Primary: MongoDB (PyMongo) with compound indexes                      |
|   Fallback: In-Memory Ring Buffer (Zero-crash resilience)               |
+-------------------------------------------------------------------------+
```

---

## 3. Data Flow Pipelines

### 3.1 Mode A — URL Analysis Pipeline
1. **Validation & Normalization:** Standardizes protocol scheme (`http://` vs `https://`), canonicalizes hostname to lowercase, validates RFC 3986 format.
2. **Feature Extraction:** Deterministically extracts 25 numerical attributes (lengths, character counts, entropy, IP markers, TLD classification) without making network socket connections.
3. **ML Inference:** The 25-dimensional vector is processed by `models/url_model.pkl` (Random Forest, 100 estimators), yielding posterior class probabilities.
4. **Heuristic Evaluation:** `services/rule_engine.py` evaluates explicit cyber threat patterns (@ redirection, raw IP host, disposable TLD).
5. **Risk Synthesis:** `services/risk_engine.py` computes the composite Risk Score (0-100), determining the operational Risk Level and actionable recommendation.
6. **Persistence:** Telemetry is written to MongoDB; the complete structured response is returned to the client.

### 3.2 Mode B — Message Analysis & Link Extraction Pipeline
1. **Linguistic Scanning:** Scans for high-urgency keywords, account suspension threats, credential requests, and OTP interception patterns.
2. **Link Extraction:** Regex scans isolate embedded URLs.
3. **NLP Vectorization:** Text is converted to a TF-IDF n-gram vector and evaluated with Logistic Regression.
4. **Cascaded URL Inspection:** Extracted links are automatically evaluated via the Mode A URL Analyzer. If any link exhibits Critical risk, the message risk is proportionally elevated.

### 3.3 Mode C — QR Code (Quishing) Pipeline
1. **Image Ingestion:** Uploaded raster image (PNG/JPEG) is validated against upload thresholds (max 10MB).
2. **Optical Decoding:** `pyzbar` decodes the 2D matrix without rendering the content in a browser environment.
3. **Pipeline Dispatch:** Valid URLs are injected directly into the URL Analyzer. The server NEVER issues HTTP GET/POST requests to the destination, guaranteeing safety against drive-by downloads.

### 3.4 Persistence & Analytics Telemetry Flow (Phase 6)
```
[User Investigation]
        ↓
[Analyzer (URL / Message)]
        ↓ In-Memory Static Analysis
[Risk Engine (Score 0-100 & Explainability)]
        ↓ Clean Structured Result
[Persistence Layer (database/mongodb.py)]
        ↓ Privacy Sanitization (database/privacy.py)
        ↓ Credentials / Passwords / Tokens Redacted
[MongoDB 'scans' Collection OR In-Memory Ring Buffer Fallback]
        ↓ Query Filtering & Indexed Sorting
[History API (/api/history) & Live Dashboard (/api/dashboard-stats)]
        ↓ Telemetry Feeds
[History Audit Table + Chart.js Threat Visualizations]
```

---

## 4. Security & Safety Principles
- **No SSRF (Server-Side Request Forgery):** The server analyzes strings lexically. It does not fetch remote HTML or resolve DNS records, eliminating SSRF and server IP leakage.
- **Fail-Safe Persistence:** If MongoDB daemon is inactive, the application seamlessly activates an in-memory queue, preventing 500 crashes during viva demos.
- **Privacy by Design:** Stored records have sensitive credentials, OTP tokens, and payment card numbers stripped prior to persistence.
- **Strict Input Sanitization:** URLs exceeding 2048 characters or messages exceeding 10,000 characters are rejected or bounded.
- **Non-Authoritative LLM Role:** LLM APIs only translate pre-calculated findings; they can never overturn the Machine Learning classifier.

---

## 5. Implementation Status

| Component | Status | Description |
|---|---|---|
| `models/url_model.pkl` (Random Forest, 100 trees) | ✅ Loaded & Active | Live Phase 4 ML Model |
| `models/feature_config.json` (25-feature map) | ✅ Active | Ordered feature vector configuration |
| `models/model_metrics.json` | ✅ Active | Real offline evaluation metrics |
| URL Analyzer end-to-end pipeline | ✅ Active | Mode A live analysis |
| Risk Engine (0-100 bounded) | ✅ Verified | Explainable risk scoring & thresholds |
| MongoDB Persistence (`scans`) | ✅ Complete (Phase 6) | PyMongo driver with 4 compound indexes |
| In-Memory Fallback | ✅ Complete (Phase 6) | Resilient ring-buffer with identical interface |
| Scan History API & UI | ✅ Complete (Phase 6) | Filterable, paginated audit log with JSON export |
| Live Analytics Dashboard | ✅ Complete (Phase 6) | Chart.js live telemetry with real empty states |
| SSRF Safety (No URL fetching) | ✅ Enforced | Static string lexical analysis only |
| Message NLP ML Model | ⏳ Phase 7 | TF-IDF + Logistic Regression text training |
