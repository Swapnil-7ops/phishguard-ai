# PhishGuard AI - Database Schema & Persistence Architecture

## 1. Database Architecture & Resilient Persistence
PhishGuard AI implements a robust, layered persistence strategy:
- **Primary Persistence Engine:** MongoDB accessed via the official **PyMongo** client driver.
- **Connection Configuration:** Environment-driven via `MONGODB_URI` (or `MONGO_URI`) and `MONGODB_DATABASE` (or `DATABASE_NAME`), with default fallback to `mongodb://localhost:27017/` and database `phishguard`.
- **Zero-Crash Resilient Fallback:** If the MongoDB daemon is offline (e.g. during an offline academic viva or standard developer laptop without a running daemon), the persistence layer transparently activates an in-memory ring-buffer queue storing the most recent 1,000 scans. The application never crashes, never stalls, and never exposes Python stack traces to the user.

---

## 2. Collection: `scans`

### 2.1 Supported Scan Vectors (Phase 6)
In Phase 6, persistence actively tracks:
1. `url`: Output of Mode A URL Analyzer (Random Forest ML + 13 Heuristic Rules + 25 Features).
2. `message`: Output of Mode B Message Analyzer (Heuristic Pattern Indicators + Cascaded URL Analysis).

### 2.2 Document JSON Schema
```json
{
  "_id": "ObjectId('6ab157...12')",
  "scan_id": "c1f7289b-8212-4212-9c41-d85718a38b12",
  "timestamp": "2026-09-21T16:15:30.123456+00:00",
  "scan_type": "url",
  "input_type": "url",
  "input": "http://admin:[REDACTED]@phish-portal.tk/login?token=[REDACTED]",
  "original_input": "http://admin:[REDACTED]@phish-portal.tk/login?token=[REDACTED]",
  "prediction": "Phishing",
  "risk_score": 88,
  "risk_level": "Critical",
  "ml_probability": 0.9421,
  "confidence": 0.9421,
  "model": "Random Forest",
  "triggered_rules": [
    "IP address used as hostname",
    "Credential harvesting keyword detected"
  ],
  "detected_indicators": [
    "IP address used as hostname",
    "Credential harvesting keyword detected"
  ],
  "features": {
    "url_length": 42,
    "has_ip_address": 1,
    "uses_https": 0,
    "suspicious_keyword_count": 2
  },
  "recommendation": "CRITICAL ALERT: Strong evidence of an active phishing attack. Avoid entering credentials.",
  "analysis_version": "1.0.0",
  "model_version": "1.0.0"
}
```

### 2.3 Field Descriptions
| Field Name | Canonical / Alias | Type | Description |
|---|---|---|---|
| `scan_id` | Canonical | `String (UUID)` | Globally unique identifier for audit tracking and referencing. |
| `timestamp` | Canonical | `String (ISO 8601)` | UTC timestamp recording exact moment analysis completed. |
| `scan_type` | Canonical | `String` | Active vector type: `'url'` or `'message'`. |
| `input_type` | Alias | `String` | Backward-compatibility alias for `scan_type`. |
| `input` | Canonical | `String` | Privacy-sanitized URL or text snippet (bounded to 500 chars). |
| `original_input` | Alias | `String` | Backward-compatibility alias for `input`. |
| `prediction` | Canonical | `String` | Categorical verdict: `'Phishing'`, `'Suspicious'`, or `'Legitimate'`. |
| `risk_score` | Canonical | `Integer` | Composite risk score bounded strictly between 0 and 100. |
| `risk_level` | Canonical | `String` | Project-defined risk band: `'Low'`, `'Medium'`, `'High'`, `'Critical'`. |
| `ml_probability` | Canonical | `Float / Null` | Posterior probability estimate from the ML model ($0.0 \le p \le 1.0$). `null` for messages pending text model training. |
| `confidence` | Alias | `Float / Null` | Backward-compatibility alias for `ml_probability`. |
| `model` | Canonical | `String` | Accurate model architecture: `'Random Forest'` for URLs, `'Heuristic + URL Cascade'` for messages. |
| `triggered_rules` | Canonical | `Array[String]` | List of deterministic security rules or NLP patterns triggered. |
| `detected_indicators`| Alias | `Array[String]` | Backward-compatibility alias for `triggered_rules`. |
| `features` | Canonical | `Object` | Extracted numerical features for URLs, or summary counts for messages. |
| `recommendation` | Canonical | `String` | Calibrated actionable advisory guidance. |
| `analysis_version` | Canonical | `String` | Model / rule engine version string (`config.MODEL_VERSION`). |

---

## 3. Database Indexes
During initialization (`init_database()`), the following indexes are guaranteed on `scans`:
1. `{"timestamp": -1}`: Optimizes chronological sorting for recent scan listings, pagination (`skip`/`limit`), and 7-day timeline aggregations.
2. `{"scan_type": 1}`: Speeds up vector filtering (`url` vs `message`).
3. `{"prediction": 1}`: Optimizes threat distribution calculations (`Phishing`, `Suspicious`, `Legitimate`).
4. `{"risk_level": 1}`: Accelerates risk tier filtering and distribution analytics.

---

## 4. Privacy & Data Sanitization Principles
PhishGuard AI analyzes user inputs in-memory before persisting. Only the copy intended for database storage is sanitized:
1. **URL Authority Credentials:** Passwords embedded in URL authority (e.g. `http://user:password@host`) are redacted to `http://user:[REDACTED]@host`.
2. **Sensitive Query Parameters:** Query keys matching sensitive tokens (`token`, `api_key`, `secret`, `password`, `jwt`, `otp`, `pin`, `session`) have values replaced with `[REDACTED]`.
3. **Message Body Redaction:** Passwords, OTP codes, credit/debit card numbers (13-19 digits), and Bearer tokens are scrubbed using regex pattern matchers.
4. **Zero Raw Storage Option:** When `STORE_RAW_CONTENT=false` is configured in `.env`, all text content is replaced with `"[Content masked by user privacy setting]"`.
5. **Length Bounds:** Persisted text is strictly bounded to 500 characters to prevent database bloat.
