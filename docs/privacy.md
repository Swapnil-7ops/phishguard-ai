# PhishGuard AI — Privacy & Data Protection Architecture

## 1. Core Privacy Philosophy

PhishGuard AI is engineered on the principle of **Privacy by Design & Default**. Investigated materials often originate from real-world security incidents and may contain confidential corporate communications, personal identification information (PII), authentication tokens, or payment card details.

To protect user confidentiality, PhishGuard AI enforces:
1. **Ephemeral In-Memory Processing:** Uploaded files and message bodies are processed in RAM and discarded immediately.
2. **Deterministic Redaction Prior to Persistence:** Sensitive tokens, credentials, and payment card numbers are permanently redacted before writing to storage.
3. **Strict External Data Minimization:** No confidential email content, headers, or personal identifiers are ever transmitted to third-party services.

---

## 2. In-Memory Lifecycle by Input Modality

| Input Modality | Storage on Disk? | Storage in Database? | External API Transmission? |
|---|---|---|---|
| **URL (Mode A)** | Never written to disk | Sanitized URL string stored | Extracted URL checked against VirusTotal if configured |
| **Message / SMS (Mode B)** | Never written to disk | Sanitized/redacted preview stored | Extracted embedded URLs only (never message text) |
| **QR Code (Mode C)** | Never written to disk (in-memory PIL) | Decoded URL stored; raw image discarded | Decoded URL checked against VirusTotal if configured |
| **Screenshot (Mode D)** | Never written to disk (in-memory PIL) | Feature counts only; raw image discarded | Extracted URL checked against VirusTotal if configured |
| **Email .EML (Mode E)** | Never written to disk (in-memory `BytesParser`) | Sanitized subject snippet & domain only; raw `.eml` discarded | Extracted URLs only (never headers, bodies, or attachments) |

---

## 3. Persistent Sanitization Layer (`database/privacy.py`)

Before any investigation record is inserted into MongoDB or the in-memory fallback ring buffer, it passes through `sanitize_scan_input()`:

### 3.1 URL Redaction
- **Authority Credentials:** URLs containing basic authentication credentials (e.g. `http://admin:secret123@portal.com/`) have the password replaced with `[REDACTED]`.
- **Query Parameter Scrubbing:** Query strings are parsed and evaluated against sensitive parameter keys:
  `password`, `passwd`, `pwd`, `pass`, `token`, `access_token`, `refresh_token`, `auth_token`, `key`, `api_key`, `secret`, `session`, `jwt`, `otp`, `pin`, `verification_code`.
  Matching parameter values are permanently transformed to `[REDACTED]`.
- **Length Clamping:** URLs are bounded to 500 characters in persistent storage.

### 3.2 Message & Text Redaction
- **Payment Card Masking:** Sequences of 13–19 digits matching credit/debit card numbers are replaced with `[CARD-REDACTED]`.
- **Credential & Secret Declarations:** Key-value pairs such as `password: secret`, `pwd = 12345`, or `pin: 9988` are masked to `[REDACTED]`.
- **One-Time Passcodes (OTP):** Verification codes matching `otp: 123456` or `code: 987654` are masked to `[REDACTED]`.
- **Bearer Tokens:** Authorization headers and bearer token strings (`bearer eyJhbGci...`) are masked to `[TOKEN-REDACTED]`.

### 3.3 Email (.EML) Sanitization
- **Raw File Discard:** The raw uploaded `.eml` file is **never stored**.
- **Body Exclusion:** Email body text (both plain text and HTML) is **never saved** in the database record.
- **Audit Identification:** The database record stores a compact sanitized summary string:
  `[Email: <filename> - <truncated subject ≤80 chars>]`.
- **Metadata Protection:** Recipient lists (`To`, `Cc`), personal sender names, and raw header blocks are excluded from database records.

---

## 4. User Privacy Configuration (`config.py`)

The application supports a centralized privacy toggle via the environment variable `STORE_RAW_CONTENT`:

```bash
# In .env
STORE_RAW_CONTENT=false
```

When set to `false`, `sanitize_message_for_storage()` and `sanitize_email_for_storage()` return:
`"[Content masked by user privacy setting]"`
ensuring that even redacted text snippets are suppressed from audit logs.

---

## 5. Threat Intelligence Privacy Boundaries

External Threat Intelligence providers (such as VirusTotal) receive **only** normalized destination URLs extracted from submitted inputs. 

PhishGuard AI explicitly guarantees that:
- No sender or recipient email addresses are submitted to VirusTotal.
- No email subjects, body contents, or headers are submitted to VirusTotal.
- No uploaded attachment files or attachment hashes are submitted to VirusTotal.
- When Threat Intelligence is unconfigured or unavailable, local machine learning and rule-based detection continue to operate with 100% functionality and zero data leakage.
