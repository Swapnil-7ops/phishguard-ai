# PhishGuard AI - REST API Documentation

Base URL: `http://localhost:5000/api`

All JSON responses follow the standardized envelope:
```json
{
  "success": true,
  "data": { ... }
}
```
Errors return:
```json
{
  "success": false,
  "error": "Descriptive error message"
}
```

---

## 1. POST /api/analyze-url
Evaluates a target URL for phishing risk using the trained Random Forest classifier, deterministic rule engine, and composite risk scoring engine. **No HTTP requests are made to the submitted URL.**

### Request
- **Method:** `POST`
- **Content-Type:** `application/json`
- **Body:**
```json
{
  "url": "http://192.168.1.100/secure/login.php?user=admin",
  "explain": false
}
```

### Response Fields (200 OK)
```json
{
  "success": true,
  "data": {
    "scan_id": "...",
    "input_url": "http://192.168.1.100/secure/login.php?user=admin",
    "normalized_url": "http://192.168.1.100/secure/login.php?user=admin",
    "prediction": "Phishing",
    "ml_prediction": "Phishing",
    "ml_probability_estimate": 0.9907,
    "confidence": 0.9907,
    "model_loaded": true,
    "model_available": true,
    "risk_score": 88,
    "risk_level": "Critical",
    "recommendation": "CRITICAL ALERT: Strong evidence of an active phishing or credential harvesting attack...",
    "reasons": [
      "Random Forest Classifier detected high statistical alignment with known phishing campaigns (99.1% confidence).",
      "IP address used as hostname (+22 pts): The URL uses a raw IPv4 address instead of a domain name.",
      "Credential harvesting keyword detected (+12 pts): The URL path contains sensitive action keywords."
    ],
    "triggered_rules": [
      {
        "rule_id": "URL_IP",
        "name": "IP address used as hostname",
        "severity": "high",
        "score_impact": 22,
        "description": "..."
      }
    ],
    "calculation_breakdown": {
      "ml_probability": 0.9907,
      "ml_base_points": 59,
      "ml_max_possible": 60,
      "raw_rule_points": 34,
      "rule_points_applied": 34,
      "rule_max_possible": 40,
      "formula": "Final Risk Score = min(100, ML_Base(59) + Rule_Impact(34)) = 88/100",
      "transparency_note": "Score is derived 60% from the Random Forest probability distribution and 40% from deterministic security rules."
    },
    "features": {
      "url_length": 42,
      "hostname_length": 13,
      "has_ip_address": 1,
      "uses_https": 0,
      "...": "25 continuous/discrete feature values"
    },
    "explanation": {
      "scan_type": "url",
      "summary": "Analysis produced a Risk Score of 88/100 (Critical Risk)...",
      "ml_evidence": {
        "model": "Random Forest Classifier",
        "phishing_probability": 0.9907,
        "phishing_probability_pct": 99.1,
        "predicted_class": "Phishing",
        "points_contributed": 59,
        "points_maximum": 60,
        "interpretation": "Elevated malicious probability was produced by the trained model."
      },
      "rule_evidence": [
        {
          "rule_id": "URL_IP",
          "rule": "IP address used as hostname",
          "description": "...",
          "severity": "high",
          "contribution": 22
        }
      ],
      "feature_evidence": [
        {
          "name": "has_ip_address",
          "value": 1,
          "sentence": "The URL uses a raw IP address instead of a conventional domain name.",
          "level": "suspicious"
        }
      ],
      "risk_contribution": {
        "ml_points": 59,
        "ml_points_maximum": 60,
        "rule_points": 34,
        "rule_points_maximum": 40,
        "total_score": 88,
        "total_maximum": 100,
        "formula": "Final Risk Score = min(100, ML_Base(59) + Rule_Impact(34)) = 88/100"
      },
      "what_does_this_mean": "Strong converging indicators of malicious or credential-harvesting activity were detected...",
      "recommendation": "CRITICAL ALERT: Strong evidence of an active phishing...",
      "investigation_stages": [
        {"stage": "Input", "detail": "URL submitted for analysis."},
        {"stage": "URL Validation & Normalization", "detail": "URL validated and normalized: ..."},
        {"stage": "Feature Extraction", "detail": "25 lexical and structural features extracted."},
        {"stage": "ML Inference", "detail": "Random Forest model applied — phishing probability: 99.1%."},
        {"stage": "Rule Evaluation", "detail": "13 security rules evaluated; 2 triggered."},
        {"stage": "Risk Calculation", "detail": "Composite score calculated: 88/100 (Critical Risk)."},
        {"stage": "Explanation Generation", "detail": "Structured evidence report assembled."}
      ],
      "global_feature_importance": {
        "label": "Global Model Feature Importance",
        "note": "Reflects the Random Forest model's global feature importance across training data. NOT a per-sample explanation.",
        "top_features": [
          {"feature": "hostname_entropy", "importance": 0.18342},
          {"feature": "url_length", "importance": 0.12411}
        ]
      }
    }
  }
}
```

### Error Responses
| Status | Condition |
|---|---|
| 400 | Missing or empty URL parameter |
| 400 | URL exceeds 2048 character limit |
| 400 | Disallowed URL scheme (javascript:, data:, file:) |
| 400 | Malformed URL with no parseable hostname |
| 500 | Internal analysis error (logged server-side, stack trace NOT exposed) |

### Risk Score Formula
```
ML_Base     = round(phishing_probability × 60)   [0–60 pts]
Rule_Impact = min(sum(triggered rule score_impacts), 40) [0–40 pts]
Risk_Score  = min(100, ML_Base + Rule_Impact)    [0–100]
```
> **Note:** The risk score is a project-defined composite index. It is NOT an ISO/NIST standardized metric.

---

## 2. POST /api/analyze-message
Scans text messages/SMS for social engineering indicators and extracts hyperlinks. Optionally runs cascaded URL analysis on discovered links.

### Request
```json
{
  "message": "URGENT: Your Chase account is suspended. Verify immediately at http://chase-unlock.tk",
  "analyze_urls": true,
  "explain": false
}
```

### Response Fields (200 OK)
```json
{
  "success": true,
  "data": {
    "prediction": "Phishing",
    "nlp_prediction": "Phishing",
    "confidence": 0.912,
    "risk_score": 85,
    "risk_level": "Critical",
    "recommendation": "HIGH SOCIAL ENGINEERING RISK: Urgent demands...",
    "detected_indicators": [
      {
        "id": "URGENCY",
        "name": "Urgent Time Pressure",
        "severity": "high",
        "severity_score": 10,
        "match_count": 1
      }
    ],
    "extracted_urls": ["http://chase-unlock.tk"],
    "url_analyses": [ ... ],
    "explanation": {
      "scan_type": "message",
      "summary": "Analysis produced a composite Risk Score of 85/100 (Critical Risk)...",
      "ml_evidence": {
        "model": "TF-IDF + Logistic Regression",
        "role": "SMS Malicious-Message / Spam Classifier",
        "dataset": "UCI SMS Spam Collection",
        "malicious_probability": 0.912,
        "malicious_probability_pct": 91.2,
        "predicted_class": "Malicious/Spam",
        "points_contributed": 50,
        "points_maximum": 55,
        "interpretation": "The TF-IDF + Logistic Regression model estimated a 91.2% SMS malicious-message probability. Elevated malicious/spam probability was produced by the trained model."
      },
      "indicator_evidence": [
        {
          "id": "URGENCY",
          "name": "Urgent Time Pressure",
          "description": "High urgency phrasing intended to induce panic...",
          "severity": "high",
          "severity_score": 10,
          "match_count": 1
        }
      ],
      "url_evidence": [
        {
          "url": "http://chase-unlock.tk",
          "prediction": "Phishing",
          "risk_score": 85,
          "risk_level": "Critical",
          "triggered_rule_count": 3
        }
      ],
      "risk_contribution": {
        "text_ml_points": 50,
        "text_ml_points_maximum": 55,
        "indicator_points": 20,
        "indicator_points_maximum": 25,
        "url_cascade_points": 17,
        "url_cascade_points_maximum": 20,
        "total_score": 85,
        "total_maximum": 100,
        "formula": "Final Risk Score = min(100, Text_ML(50) + Indicators(20) + URL_Cascade(17)) = 85/100"
      },
      "what_does_this_mean": "Strong converging indicators of malicious or credential-harvesting activity were detected...",
      "recommendation": "HIGH SOCIAL ENGINEERING RISK: Urgent demands...",
      "investigation_stages": [
        {"stage": "Input", "detail": "Message text submitted for analysis."},
        {"stage": "Heuristic Indicator Scan", "detail": "1 social engineering pattern(s) evaluated."},
        {"stage": "Text ML Inference", "detail": "TF-IDF vectorization + Logistic Regression applied — malicious/spam probability: 91.2%."},
        {"stage": "URL Extraction & Cascade Analysis", "detail": "1 embedded URL(s) detected and analyzed via URL risk pipeline."},
        {"stage": "Composite Risk Calculation", "detail": "Risk Score = 85/100 (Critical Risk)."},
        {"stage": "Explanation Generation", "detail": "Structured evidence report assembled."}
      ]
    },
    "model_loaded": true
  }
}
```

> When the NLP text model is not yet trained, `model_loaded` is `false` and `prediction` reflects heuristic mode. URL cascade analysis using the trained URL classifier still runs.

---

## 3. POST /api/analyze-qr
Decodes uploaded QR code imagery via OpenCV `QRCodeDetector` and pipelines any extracted link directly into the existing URL Analyzer. **The server never issues HTTP requests to or renders the decoded destination.**

- **Method:** `POST`
- **Content-Type:** `multipart/form-data`
- **Field:** `image` — Image file (PNG, JPG, JPEG, WEBP; max 10MB)

### Safety Guarantees
1. **Zero Outbound Traffic:** Static lexical and structural inspection only. Decoded URLs are never fetched, visited, or opened in a browser.
2. **Dangerous Schemes Blocked:** Schemes such as `javascript:`, `data:`, `file:`, `vbscript:`, and `about:` are automatically intercepted and assigned `prediction: "Blocked"` with `risk_score: 100`.
3. **Plain Text Handling:** If the QR contains plain text (e.g., wifi credentials, arbitrary notes), it returns `payload_type: "text"` with `prediction: "Informational"` and `risk_score: 0`. No URL analysis is fabricated.
4. **Ephemerality:** Uploaded QR imagery is decoded in server memory and discarded immediately; image bytes are never saved to disk.

### Response (200 OK — URL Payload)
```json
{
  "success": true,
  "data": {
    "success": true,
    "qr_detected": true,
    "qr_count": 1,
    "payload_type": "url",
    "decoded_payload": "https://secure.paypal-verification.net/login",
    "decoded_url": "https://secure.paypal-verification.net/login",
    "prediction": "Phishing",
    "risk_score": 88,
    "risk_level": "Critical",
    "ml_probability": 0.991,
    "recommendation": "CRITICAL ALERT: Strong evidence of an active phishing attempt...",
    "url_analysis": {
      "prediction": "Phishing",
      "risk_score": 88,
      "risk_level": "Critical",
      "triggered_rules": [...],
      "calculation_breakdown": {...},
      "features": {...},
      "explanation": {
        "scan_type": "url",
        "why_was_this_flagged": [...],
        "what_does_this_mean": "...",
        "risk_contribution": {...},
        "investigation_stages": [...]
      }
    },
    "scan_id": "6724a...bc"
  }
}
```

### Response (200 OK — Dangerous Scheme Blocked)
```json
{
  "success": true,
  "data": {
    "success": true,
    "qr_detected": true,
    "qr_count": 1,
    "payload_type": "dangerous_scheme",
    "decoded_payload": "javascript:alert(1)",
    "decoded_url": null,
    "url_analysis": null,
    "prediction": "Blocked",
    "risk_score": 100,
    "risk_level": "Critical",
    "recommendation": "QR code contains a 'javascript:' payload which is a dangerous scheme and has been blocked. This QR code must be treated as malicious."
  }
}
```

### Response (200 OK — Plain Text Payload)
```json
{
  "success": true,
  "data": {
    "success": true,
    "qr_detected": true,
    "qr_count": 1,
    "payload_type": "text",
    "decoded_payload": "WiFi:S:OfficeNetwork;T:WPA;P:SecretPass;;",
    "decoded_url": null,
    "url_analysis": null,
    "prediction": "Informational",
    "risk_score": 0,
    "risk_level": "Low",
    "recommendation": "The QR code was decoded successfully. The payload is plain text and does not appear to be a web URL. No URL risk analysis was performed."
  }
}
```


---

## 4. POST /api/analyze-screenshot
Accepts multipart form upload of a webpage or login screenshot (`image`), applies OpenCV contour heuristics to detect form fields and buttons, runs optional OCR keyword scanning, and cascades any extracted links through the URL analyzer without opening external URLs.

### Request
- **Content-Type:** `multipart/form-data`
- **Field:** `image` (binary, max 10 MB, `.png`, `.jpg`, `.jpeg`, `.webp`, `.bmp`)

### Response (200 OK)
```json
{
  "success": true,
  "data": {
    "risk_score": 75,
    "risk_level": "High",
    "prediction": "Phishing",
    "visual_analysis": {
      "input_fields": 2,
      "buttons": 1,
      "visual_points": 30
    },
    "explanation": { ... },
    "scan_id": "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d"
  }
}
```

---

## 5. POST /api/analyze-email
Accepts multipart form upload of a raw RFC 5322 email file (`file`), parses MIME structures, analyzes header integrity (Reply-To mismatch, Return-Path divergence), checks Authentication-Results (SPF, DKIM, DMARC), extracts social engineering triggers from the subject and body, cascades embedded URLs through the URL pipeline, and inspects attachment metadata with zero payload execution.

### Request
- **Content-Type:** `multipart/form-data`
- **Field:** `file` (binary, max 10 MB, `.eml`)

### Response (200 OK)
```json
{
  "success": true,
  "data": {
    "prediction": "Phishing",
    "risk_score": 82,
    "risk_level": "Critical",
    "recommendation": "CRITICAL EMAIL THREAT: Strong converging evidence of a spear-phishing campaign...",
    "email_analysis": {
      "headers": {
        "from": "Security Alert <alert@chase-portal.com>",
        "reply_to": "collector@adversary-host.net",
        "subject": "URGENT: Your account has been suspended"
      },
      "domains": {
        "sender_domain": "chase-portal.com",
        "reply_to_domain": "adversary-host.net"
      },
      "authentication": {
        "has_auth_header": true,
        "spf": "fail",
        "dkim": "fail",
        "dmarc": "fail",
        "indicators": [ ... ]
      },
      "header_indicators": [
        {
          "id": "HDR_REPLYTO_MISMATCH",
          "name": "Reply-To Domain Mismatch",
          "severity": "high",
          "points": 10
        }
      ],
      "subject_indicators": [
        {
          "id": "SUBJ_SUSPENSION",
          "name": "Account Suspension / Security Alert",
          "points": 5
        }
      ],
      "body_indicators": [ ... ],
      "body_ml_proxy": {
        "model": "TF-IDF + Logistic Regression (reused as body-analysis proxy)",
        "probability": 0.8821,
        "prediction": "Malicious/Spam",
        "points_contributed": 26,
        "points_maximum": 30
      },
      "extracted_urls": [
        {
          "url": "https://chase-portal.com/login",
          "risk_score": 92,
          "risk_level": "Critical",
          "prediction": "Phishing"
        }
      ],
      "attachments": [
        {
          "filename": "invoice_update.exe",
          "extension": ".exe",
          "size": 45056,
          "risk_category": "critical"
        }
      ]
    },
    "risk_breakdown": {
      "header_points": 10,
      "auth_points": 20,
      "subject_points": 5,
      "body_ml_points": 26,
      "attachment_points": 12,
      "url_cascade_points": 18,
      "raw_point_sum": 91,
      "formula": "Final Risk Score = min(100, Header(10) + Auth(20) + Subject(5) + Body_ML(26) + Attachment(12) + URL_Cascade(18)) = 82/100"
    },
    "explanation": { ... },
    "scan_id": "7b049d5b-fc77-4b71-b0db-6e676103681a"
  }
}
```

---

## 6. GET /api/history
Returns paginated, filterable investigation scan history records.

### Query Parameters
| Parameter | Type | Default | Description |
|---|---|---|---|
| `page` | Integer | 1 | 1-indexed page number. |
| `limit` | Integer | 20 | Number of records per page (max 100). |
| `offset` | Integer | 0 | Optional direct record offset (computed from `page` if provided). |
| `type` / `scan_type` | String | null | Filter by vector: `'url'`, `'message'`, `'qr'`, `'screenshot'`, `'email'`, or `'all'`. |
| `prediction` | String | null | Filter by decision: `'Phishing'`, `'Suspicious'`, `'Legitimate'`, or `'all'`. |
| `risk_level` | String | null | Filter by risk tier: `'Low'`, `'Medium'`, `'High'`, `'Critical'`, or `'all'`. |

### Response (200 OK)
```json
{
  "success": true,
  "data": {
    "count": 20,
    "offset": 0,
    "limit": 20,
    "pagination": {
      "page": 1,
      "limit": 20,
      "total": 45,
      "total_pages": 3
    },
    "scans": [
      {
        "scan_id": "c1f7289b-8212-4212-9c41-d85718a38b12",
        "timestamp": "2026-09-21T16:15:30.123456+00:00",
        "scan_type": "url",
        "input_type": "url",
        "input": "http://admin:[REDACTED]@phish-portal.tk/login",
        "original_input": "http://admin:[REDACTED]@phish-portal.tk/login",
        "prediction": "Phishing",
        "risk_score": 88,
        "risk_level": "Critical",
        "ml_probability": 0.9421,
        "confidence": 0.9421,
        "model": "Random Forest",
        "triggered_rules": [
          "IP address used as hostname"
        ],
        "detected_indicators": [
          "IP address used as hostname"
        ],
        "features": {
          "has_ip_address": 1,
          "url_length": 42
        },
        "recommendation": "CRITICAL ALERT: Strong evidence of an active phishing attack.",
        "analysis_version": "1.0.0",
        "model_version": "1.0.0"
      }
    ]
  }
}
```

---

## 6. GET /api/dashboard-stats
Returns dynamically computed telemetry metrics across stored investigations. Zero scans return genuine empty counts without fabricated numbers.

### Response (200 OK)
```json
{
  "success": true,
  "data": {
    "total_scans": 45,
    "predictions": {
      "phishing": 20,
      "legitimate": 18,
      "suspicious": 7
    },
    "risk_levels": {
      "low": 18,
      "medium": 7,
      "high": 12,
      "critical": 8
    },
    "average_risk_score": 52.4,
    "scans_over_time": [
      { "date": "2026-09-15", "count": 4 },
      { "date": "2026-09-16", "count": 7 },
      { "date": "2026-09-17", "count": 10 },
      { "date": "2026-09-18", "count": 6 },
      { "date": "2026-09-19", "count": 8 },
      { "date": "2026-09-20", "count": 5 },
      { "date": "2026-09-21", "count": 5 }
    ],
    "top_indicators": [
      { "indicator": "Lack of HTTPS transport encryption", "count": 19 },
      { "indicator": "Credential harvesting keyword detected", "count": 14 }
    ],
    "database_backend": "In-Memory Fallback",
    "mongodb_connected": false,
    "phishing_detected": 20,
    "legitimate": 18,
    "suspicious": 7
  }
}
```

---

## 7. GET /api/model-metrics
Returns training and testing evaluation metrics read from `models/model_metrics.json`.

**Response structure includes:**
- `dataset` — Name, source, sample sizes
- `models` — Per-model metrics (Accuracy, Precision, Recall, F1, Confusion Matrix) for all 3 trained architectures
- `comparison` — Side-by-side model comparison array
- `primary_model` — Deployed model name ("Random Forest")
- `feature_importance` — Gini feature importances (25 entries)

If `model_metrics.json` is absent, returns `"url_model": null` (not an error — training pending message is shown in the UI).

---

## 8. GET /api/health
Returns operational health status, model load states, and database connection mode.

```json
{
  "success": true,
  "data": {
    "status": "healthy",
    "service": "PhishGuard AI Backend",
    "version": "1.0.0",
    "database": {
      "connected": false,
      "type": "in-memory-fallback",
      "backend": "In-Memory Fallback"
    },
    "models": {
      "url_model_loaded": true,
      "text_model_loaded": false
    },
    "services": {
      "llm_explanation_enabled": false,
      "vision_screenshot_enabled": false
    }
  }
}
```

---

## Security Guarantees
- The application **never** makes HTTP/DNS requests to submitted URLs.
- Every submitted URL is treated as **untrusted text** and analyzed lexically only.
- Python stack traces are **never** exposed in API error responses.
- Request body size is enforced server-side (max 10MB for image uploads).
- Disallowed URI schemes (`javascript:`, `data:`, `file:`, `vbscript:`, `about:`) are rejected before analysis.
