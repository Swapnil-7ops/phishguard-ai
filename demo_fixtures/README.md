# PhishGuard AI — Safe Demo Fixtures Guide

This directory contains a suite of **safe, local, and non-executable demo fixtures** designed to demonstrate PhishGuard AI's multi-modal analysis capabilities:

1. **Screenshot / Visual Phishing Analyzer** (`/screenshot-analyzer`)
2. **QR / Quishing Analyzer** (`/qr-scanner`)
3. **Email (.eml) Analyzer** (`/email-analyzer`)

> **SAFETY NOTICE**:  
> All files, domains (`example.com`, `example.test`), and identities in this folder are **completely fictional**. No external websites are contacted, no live credentials or personal data are included, and no attachments contain executable or malicious code.

---

## 1. Screenshot / Visual Phishing Demo

Directory: `demo_fixtures/screenshots/`

### A. `legitimate_login.png`
- **Where to upload**: Web UI at `http://localhost:5000/screenshot-analyzer` or API endpoint `POST /api/analyze-screenshot`.
- **Intended Demonstration**:
  - Tests a standard, clean login portal ("PhishGuard Demo Portal").
  - Demonstrates typical balanced input layout (Email, Password, Sign In button).
  - Verifies that benign visual forms with no urgency or brand spoofing receive a standard, non-alarmist risk assessment.

### B. `suspicious_login.png`
- **Where to upload**: Web UI at `http://localhost:5000/screenshot-analyzer` or API endpoint `POST /api/analyze-screenshot`.
- **Intended Demonstration**:
  - Tests visual phishing indicators: alarming red warning banners, account suspension threats, high layout contour clutter, and multiple credential fields (Username, Password, OTP).
  - Demonstrates how the visual heuristic engine flags urgency and credential prompts without requiring external deep-learning models.

---

## 2. QR / Quishing Demo

Directory: `demo_fixtures/qr/`

### A. `legitimate_qr.png`
- **Where to upload**: Web UI at `http://localhost:5000/qr-scanner` or API endpoint `POST /api/analyze-qr`.
- **QR Payload**: `https://example.com/`
- **Intended Demonstration**:
  - Verifies that OpenCV `QRCodeDetector` decodes the raster matrix correctly.
  - Demonstrates clean URL cascading into the existing 25-feature URL analyzer with a benign, legitimate result.

### B. `suspicious_qr.png`
- **Where to upload**: Web UI at `http://localhost:5000/qr-scanner` or API endpoint `POST /api/analyze-qr`.
- **QR Payload**: `https://example.test/verify-account-login`
- **Intended Demonstration**:
  - Tests decoding of a fictional suspicious link masking a credential call-to-action.
  - Demonstrates that the decoded link is safely routed into the lexical URL analyzer **without any outbound HTTP connection or browsing**.

*Reference*: See `demo_fixtures/qr/qr_payloads.txt` for exact machine-readable payload strings.

---

## 3. Email (.eml) Analyzer Demo

Directory: `demo_fixtures/emails/`

### A. `legitimate_email.eml`
- **Where to upload**: Web UI at `http://localhost:5000/email-analyzer` or API endpoint `POST /api/analyze-email`.
- **Subject**: `Your Demo Account Information`
- **Sender**: `support@example.com`
- **Intended Demonstration**:
  - Tests clean RFC 5322 parsing with authentic header structure.
  - Demonstrates passing SPF, DKIM, and DMARC authentication checks.
  - Verifies that benign notifications produce a "Low" risk level with 0 penalty points across header and auth buckets.

### B. `phishing_email.eml`
- **Where to upload**: Web UI at `http://localhost:5000/email-analyzer` or API endpoint `POST /api/analyze-email`.
- **Subject**: `Urgent Account Verification Required`
- **Sender**: `security@example.test` (Reply-To: `verify@example.test`)
- **Intended Demonstration**:
  - Tests social-engineering urgency detection ("immediate verification", "account suspension").
  - Tests authentication forensics showing `spf=softfail`, `dkim=fail`, and `dmarc=fail`.
  - Tests embedded link extraction (`https://example.test/verify-account`) and URL cascade scoring.

### C. `demo_attachment.txt` & `email_with_attachment.eml`
- **Where to upload**: `email_with_attachment.eml` to `/email-analyzer`.
- **Intended Demonstration**:
  - Tests attachment metadata extraction without file execution.
  - Demonstrates that safe, harmless plain-text attachments are recognized and categorized with 0 attachment risk points.

---

## 4. Re-generating Fixtures

To re-generate all demo fixtures at any time, run:

```bash
python demo_fixtures/generate_fixtures.py
```
