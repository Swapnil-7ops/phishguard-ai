"""
privacy.py - Privacy Sanitization & Redaction Layer

WHAT: Scrubs sensitive credentials, tokens, and payment card patterns from
     scans prior to database persistence.
WHY: Scanned content may include sensitive victim data, temporary tokens,
     or credentials that should never be stored in persistent audit logs.
HOW: Uses regex pattern matching and URL query parameter parsing to sanitize
     passwords, auth tokens, OTPs, and card numbers.
NOTE: This runs ONLY on the persisted representation. The in-memory analysis
     pipeline operates on the original input untouched.
"""
import re
from urllib.parse import urlparse, urlunparse, parse_qsl, urlencode
from typing import Optional


# Sensitive parameter keys to redact in URLs
SENSITIVE_URL_PARAMS = {
    'password', 'passwd', 'pwd', 'pass',
    'token', 'access_token', 'refresh_token', 'auth_token', 'id_token',
    'key', 'api_key', 'apikey', 'secret', 'client_secret',
    'session', 'session_id', 'sessionid', 'jwt',
    'auth', 'authorization', 'signature', 'sig',
    'otp', 'pin', 'code', 'verification_code'
}


def sanitize_url_for_storage(raw_url: str, max_length: int = 500) -> str:
    """
    Sanitize a URL for persistent storage:
    - Redacts passwords embedded in authority (e.g. user:password@host)
    - Redacts values of sensitive query parameters (e.g. ?token=xyz -> ?token=[REDACTED])
    - Enforces max length bound
    """
    if not raw_url or not isinstance(raw_url, str):
        return ""

    url_str = raw_url.strip()

    # Mask embedded userinfo password
    # e.g., http://admin:supersecret@example.com/ -> http://admin:[REDACTED]@example.com/
    url_str = re.sub(
        r'(://[^/@:]+):([^/@]+)@',
        r'\1:[REDACTED]@',
        url_str
    )

    try:
        parsed = urlparse(url_str)
        if parsed.query:
            query_pairs = parse_qsl(parsed.query, keep_blank_values=True)
            sanitized_pairs = []
            for k, v in query_pairs:
                if k.lower() in SENSITIVE_URL_PARAMS:
                    sanitized_pairs.append((k, '[REDACTED]'))
                else:
                    sanitized_pairs.append((k, v))
            new_query = urlencode(sanitized_pairs)
            url_str = urlunparse((
                parsed.scheme,
                parsed.netloc,
                parsed.path,
                parsed.params,
                new_query,
                parsed.fragment
            ))
    except Exception:
        # If parsing fails, fall back to safe regex-based parameter masking
        for param in SENSITIVE_URL_PARAMS:
            url_str = re.sub(
                rf'([?&]{param}=)[^&#\s]+',
                r'\1[REDACTED]',
                url_str,
                flags=re.IGNORECASE
            )

    return url_str[:max_length]


def sanitize_message_for_storage(raw_message: str, store_raw: bool = True, max_length: int = 500) -> str:
    """
    Sanitize text message content for persistent storage:
    - If store_raw is False, returns a generic placeholder
    - Redacts passwords, OTPs, PINs, card numbers, and bearer tokens
    - Enforces max length bound
    """
    if not raw_message or not isinstance(raw_message, str):
        return ""

    if not store_raw:
        return "[Content masked by user privacy setting]"

    text = raw_message.strip()

    # 1. Redact credit / debit card numbers (13-19 digits, possibly with spaces or dashes)
    text = re.sub(r'\b(?:\d[ -]*?){13,19}\b', '[CARD-REDACTED]', text)

    # 2. Redact password / secret declarations
    text = re.sub(
        r'(?i)\b(password|passwd|pwd|pin|passcode|secret)\s*[:=]\s*\S+',
        r'\1: [REDACTED]',
        text
    )

    # 3. Redact OTP / verification codes
    text = re.sub(
        r'(?i)\b(otp|one[ -]?time password|verification code|security code)\s*[:=]\s*\d+',
        r'\1: [REDACTED]',
        text
    )

    # 4. Redact Bearer tokens
    text = re.sub(
        r'(?i)\b(bearer\s+)[a-zA-Z0-9_\-\.]{20,}',
        r'\1[TOKEN-REDACTED]',
        text
    )

    return text[:max_length]


def sanitize_email_for_storage(raw_input: str, store_raw: bool = True, max_length: int = 500) -> str:
    """
    Sanitize email summary/subject information for persistent storage:
    - Never stores full email bodies.
    - Sanitizes passwords, OTPs, and card patterns.
    - Enforces max length bound.
    """
    if not raw_input or not isinstance(raw_input, str):
        return ""

    if not store_raw:
        return "[Email metadata masked by user privacy setting]"

    return sanitize_message_for_storage(raw_input, store_raw=store_raw, max_length=max_length)


def sanitize_scan_input(raw_input: str, input_type: str, store_raw: bool = True) -> str:
    """Convenience dispatcher to sanitize input according to scan_type."""
    if input_type == 'url':
        return sanitize_url_for_storage(raw_input)
    elif input_type == 'message':
        return sanitize_message_for_storage(raw_input, store_raw=store_raw)
    elif input_type == 'qr':
        # QR decoded URLs are sanitized the same way as direct URL inputs
        return sanitize_url_for_storage(raw_input)
    elif input_type in ('email', 'eml'):
        return sanitize_email_for_storage(raw_input, store_raw=store_raw)
    else:
        return (raw_input or "")[:500]


