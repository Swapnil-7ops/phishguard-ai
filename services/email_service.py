"""
email_service.py - EML Email Phishing Analysis Service

WHAT: Accepts uploaded .eml files and applies Python standard-library email
      parsing, header forensics, authentication verification (SPF/DKIM/DMARC headers),
      subject social-engineering heuristics, sanitized HTML/plain-text extraction,
      URL extraction with cascade to the existing URL Analyzer, and attachment
      metadata inspection.
WHY:  Email is the primary vector for spear-phishing, credential harvesting, and
      business email compromise (BEC).
HOW:
  1. Validate .eml file (size <= 10 MB, extension, parseability).
  2. Parse MIME structure via email.parser.BytesParser and email.policy.default.
  3. Extract headers (From, To, Reply-To, Return-Path, Subject, Date, Message-ID).
  4. Perform header analysis (Reply-To mismatch, Return-Path divergence, formatting).
  5. Parse Authentication-Results header (SPF, DKIM, DMARC) if present.
  6. Analyze subject for social-engineering triggers (urgency, credential, financial).
  7. Extract plain-text and HTML bodies using safe HTML text stripping (never execute).
  8. Extract and deduplicate URLs from plain text and HTML href attributes.
  9. Cascade extracted URLs to services.url_analyzer.analyze_url() (max URL risk applied).
 10. Inspect attachment metadata (extensions, double extensions, sizes, MIME types).
 11. Run TF-IDF + Logistic Regression (reused as body-analysis proxy) on body text.
 12. Calculate composite risk via services.risk_engine.calculate_email_risk().
 13. Assemble structured explanation via services.explanation_builder.build_email_explanation().

SECURITY:
  - NEVER executes email attachments or imports their binary contents.
  - NEVER fetches, opens, or executes extracted URLs.
  - NEVER renders raw untrusted HTML into the DOM without sanitization.
  - NEVER sends email bodies, headers, or attachments to external Threat Intelligence.
  - Only extracted destination URLs are looked up in Threat Intelligence.
  - Processes .eml entirely in-memory; never persists raw .eml to disk.

LIMITATIONS:
  - Header authentication results are read directly from the supplied email's
    Authentication-Results header; no active external DNS/DMARC queries are made.
  - The text classifier is the UCI SMS-trained model reused as a proxy signal for
    body social-engineering patterns, NOT an email-specific model.
"""

import io
import re
import html
import logging
from html.parser import HTMLParser
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from typing import Dict, Any, List, Optional, Tuple

from config import config
from services.url_analyzer import analyze_url
from services.risk_engine import calculate_email_risk
from services.explanation_builder import build_email_explanation
from services.message_analyzer import extract_indicators, load_text_models

logger = logging.getLogger(__name__)

# File upload constants
MAX_EML_BYTES = 10 * 1024 * 1024  # 10 MB
ALLOWED_EMAIL_EXTENSIONS = {'.eml'}

# Dangerous attachment extensions
EXECUTABLE_EXTENSIONS = {'.exe', '.scr', '.com', '.bat', '.cmd', '.msi', '.pif', '.cpl', '.gadget'}
SCRIPT_EXTENSIONS = {'.js', '.jse', '.vbs', '.vbe', '.ps1', '.psm1', '.wsf', '.wsh', '.hta'}
MACRO_EXTENSIONS = {'.docm', '.xlsm', '.pptm', '.dotm', '.xltm', '.potm'}
ARCHIVE_EXTENSIONS = {'.zip', '.rar', '.7z', '.tar', '.gz', '.bz2', '.iso', '.img'}

# Subject social engineering patterns
SUBJECT_RULES = [
    {
        "id": "SUBJ_URGENCY",
        "name": "Urgent Time Pressure in Subject",
        "severity": "high",
        "points": 5,
        "description": "Subject uses alarming words to pressure hurried action.",
        "pattern": r'\b(urgent|immediately|asap|action required|final notice|expires? today|important update|immediate response)\b'
    },
    {
        "id": "SUBJ_SUSPENSION",
        "name": "Account Suspension / Security Alert",
        "severity": "high",
        "points": 5,
        "description": "Subject references account deactivation, locking, or unauthorized access.",
        "pattern": r'\b(suspend(ed)?|lock(ed)?|block(ed)?|deactivat(ed)?|security alert|unauthorized login|compromised|terminated)\b'
    },
    {
        "id": "SUBJ_CREDENTIAL",
        "name": "Credential Verification Subject",
        "severity": "high",
        "points": 5,
        "description": "Subject requests password resets, identity verification, or login confirmation.",
        "pattern": r'\b(verify your (account|identity|email|password)|password reset|confirm your login|update your credentials)\b'
    },
    {
        "id": "SUBJ_FINANCIAL",
        "name": "Billing / Payment / Invoice Subject",
        "severity": "medium",
        "points": 4,
        "description": "Subject refers to unexpected bills, failed transactions, refunds, or invoices.",
        "pattern": r'\b(invoice|unpaid (bill|fee)|payment (declined|failed|receipt)|refund pending|wire transfer|direct deposit)\b'
    }
]


# ---------------------------------------------------------------------------
# HTML Parser for Safe Text & URL Extraction
# ---------------------------------------------------------------------------

class SafeHTMLBodyParser(HTMLParser):
    """
    Parses HTML email body to safely extract:
      1. Plain text representation (excluding script/style tags).
      2. Hyperlinks from <a> href attributes.
      3. Security indicators (presence of <script>, <iframe>, javascript: links, inline handlers).
    """

    def __init__(self):
        super().__init__()
        self._text_chunks: List[str] = []
        self._in_ignored_tag = False
        self._ignored_tags = {'script', 'style', 'head', 'meta', 'title'}
        self.extracted_urls: List[str] = []
        self.security_flags: List[Dict[str, Any]] = []

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]):
        tag_lower = tag.lower()
        if tag_lower in self._ignored_tags:
            self._in_ignored_tag = True

        attrs_dict = {k.lower(): v for k, v in attrs if k}

        # Check for dangerous tag injection
        if tag_lower == 'script':
            self.security_flags.append({
                "type": "SCRIPT_TAG_INJECTION",
                "severity": "critical",
                "description": "Active <script> tag detected inside HTML email body."
            })
        elif tag_lower == 'iframe':
            self.security_flags.append({
                "type": "IFRAME_INJECTION",
                "severity": "high",
                "description": "Hidden or embedded <iframe> detected inside HTML email body."
            })

        # Check for inline event handlers (e.g. onclick, onload, onerror)
        for attr_name in attrs_dict:
            if attr_name.startswith('on'):
                self.security_flags.append({
                    "type": "INLINE_EVENT_HANDLER",
                    "severity": "high",
                    "description": f"Executable inline event handler '{attr_name}' detected on <{tag_lower}>."
                })
                break

        # Extract href attributes from anchor tags
        if tag_lower == 'a' and 'href' in attrs_dict:
            href_val = attrs_dict['href']
            if href_val:
                href_clean = href_val.strip()
                href_lower = href_clean.lower()
                if href_lower.startswith('javascript:'):
                    self.security_flags.append({
                        "type": "JAVASCRIPT_URI",
                        "severity": "critical",
                        "description": f"Dangerous javascript: URI detected in link destination: {href_clean[:60]}"
                    })
                elif href_lower.startswith('data:'):
                    self.security_flags.append({
                        "type": "DATA_URI",
                        "severity": "medium",
                        "description": "Data URI detected in link destination."
                    })
                elif href_lower.startswith(('http://', 'https://')):
                    self.extracted_urls.append(href_clean)

    def handle_endtag(self, tag: str):
        if tag.lower() in self._ignored_tags:
            self._in_ignored_tag = False

    def handle_data(self, data: str):
        if not self._in_ignored_tag:
            self._text_chunks.append(data)

    def get_text(self) -> str:
        return re.sub(r'\s+', ' ', ' '.join(self._text_chunks)).strip()


# ---------------------------------------------------------------------------
# Validation Functions
# ---------------------------------------------------------------------------

def validate_eml_file(file_bytes: bytes, filename: str) -> None:
    """
    Validate that uploaded file is a valid .eml file.
    Raises ValueError with descriptive reason if invalid.
    """
    if not file_bytes or len(file_bytes) == 0:
        raise ValueError("The uploaded email file is empty (0 bytes).")

    if len(file_bytes) > MAX_EML_BYTES:
        raise ValueError(f"Email file size ({len(file_bytes) / 1024 / 1024:.1f} MB) exceeds maximum allowed limit (10 MB).")

    ext = "." + filename.lower().rsplit(".", 1)[-1] if "." in filename else ""
    if ext not in ALLOWED_EMAIL_EXTENSIONS:
        raise ValueError(f"Unsupported file extension '{ext}'. Only .eml files are accepted.")

    # Verify basic email parseability
    try:
        msg = BytesParser(policy=policy.default).parsebytes(file_bytes)
        # An email should at least have some headers or MIME structure
        if not msg.keys():
            raise ValueError("Unable to parse email headers; file does not contain valid RFC 5322/MIME headers.")
    except Exception as e:
        if isinstance(e, ValueError):
            raise
        raise ValueError(f"Malformed email structure: {str(e)}")


# ---------------------------------------------------------------------------
# Domain Extraction Helper
# ---------------------------------------------------------------------------

def _extract_domain_from_email_addr(header_value: Optional[str]) -> Optional[str]:
    """Extract and normalize lowercased domain from an email address header."""
    if not header_value:
        return None
    _, addr = parseaddr(header_value)
    if not addr or '@' not in addr:
        # Fallback to regex if parseaddr fails
        match = re.search(r'[\w\.-]+@([\w\.-]+\.\w+)', header_value)
        return match.group(1).lower() if match else None
    return addr.split('@')[-1].strip().lower()


def _get_raw_header(msg: Any, name: str) -> str:
    """Safely get header string, falling back to raw un-mangled string if policy mangles it."""
    val = msg.get(name)
    if val is not None:
        s_val = str(val)
        if s_val and s_val != '<>':
            return s_val
    if hasattr(msg, '_headers') and msg._headers:
        for k, v in msg._headers:
            if k.lower() == name.lower():
                return str(v)
    return str(val or '')


# ---------------------------------------------------------------------------
# Parsing Function
# ---------------------------------------------------------------------------

def parse_eml(file_bytes: bytes) -> Dict[str, Any]:
    """
    Parse .eml bytes into a structured normalized metadata dictionary using stdlib email.
    """
    msg = BytesParser(policy=policy.default).parsebytes(file_bytes)

    # Standard headers using raw extractor to preserve evasive/malformed headers
    from_header = _get_raw_header(msg, 'from')
    to_header = _get_raw_header(msg, 'to')
    cc_header = _get_raw_header(msg, 'cc')
    reply_to = _get_raw_header(msg, 'reply-to')
    return_path = _get_raw_header(msg, 'return-path')
    subject = _get_raw_header(msg, 'subject')
    date_str = _get_raw_header(msg, 'date')
    message_id = _get_raw_header(msg, 'message-id')
    content_type = str(msg.get_content_type() or '')
    auth_results = _get_raw_header(msg, 'authentication-results')

    # Received headers (can have multiple)
    received_headers = [str(r) for r in msg.get_all('received', [])]

    # Domain extractions
    sender_domain = _extract_domain_from_email_addr(from_header)
    reply_to_domain = _extract_domain_from_email_addr(reply_to)
    return_path_domain = _extract_domain_from_email_addr(return_path)

    # Body extraction
    plain_body = ""
    html_body = ""
    attachments: List[Dict[str, Any]] = []

    if msg.is_multipart():
        for part in msg.walk():
            part_content_type = part.get_content_type()
            part_disposition = str(part.get_content_disposition() or '').lower()
            filename = part.get_filename()

            if filename or part_disposition in ('attachment', 'inline') and part_content_type not in ('text/plain', 'text/html'):
                # Treat as attachment
                try:
                    payload = part.get_payload(decode=True) or b''
                    size = len(payload)
                except Exception:
                    size = 0

                clean_filename = filename or "unnamed_attachment"
                ext = ("." + clean_filename.lower().rsplit(".", 1)[-1]) if "." in clean_filename else ""

                attachments.append({
                    "filename": clean_filename,
                    "content_type": part_content_type,
                    "content_disposition": part_disposition or "attachment",
                    "size": size,
                    "extension": ext
                })
            elif part_content_type == 'text/plain' and not plain_body:
                try:
                    payload_bytes = part.get_payload(decode=True)
                    charset = part.get_content_charset() or 'utf-8'
                    plain_body = payload_bytes.decode(charset, errors='replace') if payload_bytes else ""
                except Exception:
                    plain_body = str(part.get_payload() or "")
            elif part_content_type == 'text/html' and not html_body:
                try:
                    payload_bytes = part.get_payload(decode=True)
                    charset = part.get_content_charset() or 'utf-8'
                    html_body = payload_bytes.decode(charset, errors='replace') if payload_bytes else ""
                except Exception:
                    html_body = str(part.get_payload() or "")
    else:
        # Non-multipart message
        try:
            payload_bytes = msg.get_payload(decode=True)
            charset = msg.get_content_charset() or 'utf-8'
            decoded = payload_bytes.decode(charset, errors='replace') if payload_bytes else str(msg.get_payload() or "")
        except Exception:
            decoded = str(msg.get_payload() or "")

        if content_type == 'text/html':
            html_body = decoded
        else:
            plain_body = decoded

    return {
        "headers": {
            "from": from_header,
            "to": to_header,
            "cc": cc_header,
            "reply_to": reply_to,
            "return_path": return_path,
            "subject": subject,
            "date": date_str,
            "message_id": message_id,
            "content_type": content_type,
            "authentication_results": auth_results,
            "received_count": len(received_headers),
        },
        "domains": {
            "sender_domain": sender_domain,
            "reply_to_domain": reply_to_domain,
            "return_path_domain": return_path_domain,
        },
        "body": {
            "plain_text": plain_body,
            "html": html_body,
        },
        "attachments": attachments,
    }


# ---------------------------------------------------------------------------
# Header Forensics
# ---------------------------------------------------------------------------

def analyze_headers(parsed_email: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Evaluate explainable cybersecurity header anomalies.
    Returns list of indicator dictionaries with severity and points.
    """
    indicators = []
    headers = parsed_email.get("headers", {})
    domains = parsed_email.get("domains", {})

    sender_dom = domains.get("sender_domain")
    reply_to_dom = domains.get("reply_to_domain")
    return_path_dom = domains.get("return_path_domain")

    # 1. Reply-To Domain Mismatch
    if sender_dom and reply_to_dom and sender_dom != reply_to_dom:
        indicators.append({
            "id": "HDR_REPLYTO_MISMATCH",
            "name": "Reply-To Domain Mismatch",
            "severity": "high",
            "points": 10,
            "description": f"The Reply-To domain ('{reply_to_dom}') differs from sender domain ('{sender_dom}'). Replies will be routed to a different host."
        })

    # 2. Return-Path Domain Mismatch
    if sender_dom and return_path_dom and sender_dom != return_path_dom:
        # Ignore common mail services like amazonses, sendgrid, mailgun if sender is different
        indicators.append({
            "id": "HDR_RETURNPATH_MISMATCH",
            "name": "Return-Path Domain Divergence",
            "severity": "medium",
            "points": 5,
            "description": f"Return-Path domain ('{return_path_dom}') does not match sender domain ('{sender_dom}')."
        })

    # 3. Missing Critical Delivery Headers
    date_val = headers.get("date", "").strip()
    msg_id = headers.get("message_id", "").strip()
    if not date_val:
        indicators.append({
            "id": "HDR_MISSING_DATE",
            "name": "Missing Date Header",
            "severity": "low",
            "points": 3,
            "description": "Standard RFC 5322 Date header is missing from message headers."
        })
    if not msg_id:
        indicators.append({
            "id": "HDR_MISSING_MSGID",
            "name": "Missing Message-ID Header",
            "severity": "low",
            "points": 3,
            "description": "RFC 5322 Message-ID header is missing, common in automated mass-mailing and botnets."
        })

    # 4. Suspicious Sender Formatting (Multiple @, display name spoofing)
    from_raw = headers.get("from", "")
    if from_raw.count('@') > 1:
        indicators.append({
            "id": "HDR_MULTIPLE_AT",
            "name": "Multiple '@' Symbols in Sender Header",
            "severity": "high",
            "points": 7,
            "description": "Sender header contains multiple '@' characters, an evasion technique used to disguise true source."
        })

    # Display name spoofing (e.g. "PayPal Support <evil@attacker.com>")
    display_name, addr = parseaddr(from_raw)
    if display_name and '@' in display_name:
        indicators.append({
            "id": "HDR_DISPLAY_NAME_EMAIL",
            "name": "Email Address in Sender Display Name",
            "severity": "medium",
            "points": 5,
            "description": f"Display name '{display_name}' embeds an email address to deceive mobile email clients."
        })

    return indicators


# ---------------------------------------------------------------------------
# Authentication Results Forensics (SPF, DKIM, DMARC)
# ---------------------------------------------------------------------------

def analyze_authentication(parsed_email: Dict[str, Any]) -> Dict[str, Any]:
    """
    Parse and evaluate SPF, DKIM, and DMARC from Authentication-Results header.
    Does NOT conduct live network DNS lookups.
    """
    auth_header = parsed_email.get("headers", {}).get("authentication_results", "")
    if not auth_header:
        return {
            "has_auth_header": False,
            "spf": "not_present",
            "dkim": "not_present",
            "dmarc": "not_present",
            "indicators": [],
            "auth_points": 0
        }

    lower_auth = auth_header.lower()

    # Regex search for verdicts
    spf_match = re.search(r'\bspf=(\w+)', lower_auth)
    dkim_match = re.search(r'\bdkim=(\w+)', lower_auth)
    dmarc_match = re.search(r'\bdmarc=(\w+)', lower_auth)

    spf_status = spf_match.group(1) if spf_match else "not_specified"
    dkim_status = dkim_match.group(1) if dkim_match else "not_specified"
    dmarc_status = dmarc_match.group(1) if dmarc_match else "not_specified"

    indicators = []
    points = 0

    # Evaluate DMARC
    if dmarc_status in ("fail", "permerror"):
        indicators.append({
            "id": "AUTH_DMARC_FAIL",
            "name": "DMARC Authentication Failure",
            "severity": "high",
            "points": 10,
            "description": f"Authentication-Results header recorded DMARC failure (status: '{dmarc_status}')."
        })
        points += 10

    # Evaluate SPF
    if spf_status in ("fail", "permerror"):
        indicators.append({
            "id": "AUTH_SPF_FAIL",
            "name": "SPF Authentication Failure",
            "severity": "high",
            "points": 7,
            "description": f"Authentication-Results header recorded SPF failure (status: '{spf_status}')."
        })
        points += 7
    elif spf_status == "softfail":
        indicators.append({
            "id": "AUTH_SPF_SOFTFAIL",
            "name": "SPF Softfail",
            "severity": "medium",
            "points": 4,
            "description": "Authentication-Results header reported SPF softfail (~all)."
        })
        points += 4

    # Evaluate DKIM
    if dkim_status in ("fail", "permerror"):
        indicators.append({
            "id": "AUTH_DKIM_FAIL",
            "name": "DKIM Signature Verification Failure",
            "severity": "high",
            "points": 7,
            "description": f"Authentication-Results header recorded DKIM verification failure (status: '{dkim_status}')."
        })
        points += 7

    return {
        "has_auth_header": True,
        "spf": spf_status,
        "dkim": dkim_status,
        "dmarc": dmarc_status,
        "indicators": indicators,
        "auth_points": min(points, 20)
    }


# ---------------------------------------------------------------------------
# Subject Analysis
# ---------------------------------------------------------------------------

def analyze_subject(subject: str) -> List[Dict[str, Any]]:
    """
    Analyze email subject for social-engineering indicators.
    """
    indicators = []
    if not subject:
        indicators.append({
            "id": "SUBJ_EMPTY",
            "name": "Empty Subject Line",
            "severity": "low",
            "points": 2,
            "description": "Email has no subject header, common in automated probing."
        })
        return indicators

    subj_lower = subject.lower()
    for rule in SUBJECT_RULES:
        if re.search(rule["pattern"], subj_lower, re.IGNORECASE):
            indicators.append({
                "id": rule["id"],
                "name": rule["name"],
                "severity": rule["severity"],
                "points": rule["points"],
                "description": rule["description"]
            })
    return indicators


# ---------------------------------------------------------------------------
# Safe Body Text Extraction
# ---------------------------------------------------------------------------

def extract_body_text_and_security(parsed_email: Dict[str, Any]) -> Tuple[str, str, List[str], List[Dict[str, Any]]]:
    """
    Safely extract plain text and HTML text, and detect HTML script/security flags.

    Returns:
        (plain_text, html_visible_text, html_extracted_urls, html_security_flags)
    """
    body_dict = parsed_email.get("body", {})
    plain_text = body_dict.get("plain_text", "")
    raw_html = body_dict.get("html", "")

    html_visible_text = ""
    html_urls: List[str] = []
    security_flags: List[Dict[str, Any]] = []

    if raw_html:
        parser = SafeHTMLBodyParser()
        try:
            parser.feed(raw_html)
            html_visible_text = parser.get_text()
            html_urls = parser.extracted_urls
            security_flags = parser.security_flags
        except Exception as e:
            logger.debug(f"Error parsing HTML body with SafeHTMLBodyParser: {e}")
            # Fallback simple tag strip
            html_visible_text = re.sub(r'<[^>]+>', ' ', raw_html)
            html_visible_text = re.sub(r'\s+', ' ', html_visible_text).strip()

    return plain_text, html_visible_text, html_urls, security_flags


# ---------------------------------------------------------------------------
# URL Extraction & Deduplication
# ---------------------------------------------------------------------------

def extract_urls_from_email(plain_text: str, html_urls: List[str]) -> List[str]:
    """
    Extract and deduplicate all URLs found in the plain text and HTML link elements.
    """
    url_regex = r'(?:https?:\/\/|www\.)[a-zA-Z0-9.\-_]+(?:\/[a-zA-Z0-9._~:/?#[\]@!$&\'()*+,;=%-]*)?'
    found_plain = re.findall(url_regex, plain_text or "", flags=re.IGNORECASE)

    all_raw = list(found_plain) + list(html_urls)
    cleaned = []

    for u in all_raw:
        u_clean = u.rstrip('.,;!?)\'\"')
        if u_clean.lower().startswith('www.'):
            u_clean = 'http://' + u_clean
        if u_clean.lower().startswith(('http://', 'https://')):
            cleaned.append(u_clean)

    # Deduplicate while preserving order
    return list(dict.fromkeys(cleaned))


# ---------------------------------------------------------------------------
# Attachment Metadata Inspection
# ---------------------------------------------------------------------------

def analyze_attachments(parsed_email: Dict[str, Any]) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], int]:
    """
    Examine attachment metadata without executing or opening file payloads.

    Returns:
        (inspected_attachments, attachment_indicators, attachment_risk_points)
    """
    raw_attachments = parsed_email.get("attachments", [])
    inspected = []
    indicators = []
    points = 0

    for att in raw_attachments:
        fname = att.get("filename", "unnamed")
        ext = att.get("extension", "").lower()
        size = att.get("size", 0)
        ctype = att.get("content_type", "")
        disp = att.get("content_disposition", "attachment")

        risk_category = "benign"
        risk_note = "Standard file format"

        # Check for path traversal in filename
        if ".." in fname or "/" in fname or "\\" in fname:
            indicators.append({
                "id": "ATT_PATH_TRAVERSAL",
                "name": "Path Traversal in Attachment Filename",
                "severity": "high",
                "points": 10,
                "description": f"Attachment filename '{fname}' contains path traversal characters."
            })
            points += 10
            risk_category = "dangerous"
            risk_note = "Path traversal attempted in filename"

        # Check double extensions (e.g., invoice.pdf.exe)
        parts = fname.split('.')
        if len(parts) > 2:
            inner_ext = "." + parts[-2].lower()
            if inner_ext in ('.pdf', '.doc', '.docx', '.xls', '.xlsx', '.txt') and ext in EXECUTABLE_EXTENSIONS | SCRIPT_EXTENSIONS:
                indicators.append({
                    "id": "ATT_DOUBLE_EXTENSION",
                    "name": "Deceptive Double Extension",
                    "severity": "critical",
                    "points": 12,
                    "description": f"Attachment '{fname}' uses double extension spoofing to disguise executable payload."
                })
                points += 12
                risk_category = "critical"
                risk_note = "Double extension disguising executable"

        # Check extension categories
        if ext in EXECUTABLE_EXTENSIONS:
            indicators.append({
                "id": "ATT_EXECUTABLE",
                "name": "Executable Attachment",
                "severity": "critical",
                "points": 12,
                "description": f"Attachment '{fname}' is an executable file ({ext})."
            })
            points += 12
            risk_category = "critical"
            risk_note = "Executable file extension"
        elif ext in SCRIPT_EXTENSIONS:
            indicators.append({
                "id": "ATT_SCRIPT",
                "name": "Script File Attachment",
                "severity": "high",
                "points": 10,
                "description": f"Attachment '{fname}' is a script file ({ext})."
            })
            points += 10
            risk_category = "high"
            risk_note = "Script file extension"
        elif ext in MACRO_EXTENSIONS:
            indicators.append({
                "id": "ATT_MACRO",
                "name": "Macro-Enabled Office Document",
                "severity": "medium",
                "points": 7,
                "description": f"Attachment '{fname}' is a macro-enabled Office document ({ext})."
            })
            points += 7
            risk_category = "medium"
            risk_note = "Macro-enabled document format"
        elif ext in ARCHIVE_EXTENSIONS:
            indicators.append({
                "id": "ATT_ARCHIVE",
                "name": "Archive Attachment",
                "severity": "low",
                "points": 3,
                "description": f"Attachment '{fname}' is an archive ({ext}); archives can bundle uninspected files."
            })
            points += 3
            risk_category = "suspicious"
            risk_note = "Compressed archive"

        inspected.append({
            "filename": fname,
            "extension": ext,
            "size": size,
            "content_type": ctype,
            "disposition": disp,
            "risk_category": risk_category,
            "risk_note": risk_note
        })

    return inspected, indicators, min(points, 15)


# ---------------------------------------------------------------------------
# Complete Email Pipeline Orchestrator
# ---------------------------------------------------------------------------

def process_email_analysis(file_bytes: bytes, filename: str) -> Dict[str, Any]:
    """
    Main entry point for .eml email phishing analysis.
    Executes complete in-memory pipeline:
      Validation -> Parsing -> Headers -> Auth -> Subject -> Body -> URLs -> Attachments -> Risk -> Explanation

    Args:
        file_bytes: Raw .eml file bytes.
        filename: Uploaded filename.

    Returns:
        Structured result dictionary conforming to API contracts.
    """
    # 1. Validation
    validate_eml_file(file_bytes, filename)

    # 2. Parse MIME structure
    parsed_email = parse_eml(file_bytes)

    # 3. Header Analysis
    header_indicators = analyze_headers(parsed_email)
    raw_header_points = sum(ind.get("points", 0) for ind in header_indicators)
    header_points = min(raw_header_points, 20)

    # 4. Authentication Analysis (SPF, DKIM, DMARC)
    auth_data = analyze_authentication(parsed_email)
    auth_indicators = auth_data.get("indicators", [])
    auth_points = min(auth_data.get("auth_points", 0), 20)

    # 5. Subject Analysis
    subject_str = parsed_email.get("headers", {}).get("subject", "")
    subject_indicators = analyze_subject(subject_str)
    raw_subj_points = sum(ind.get("points", 0) for ind in subject_indicators)
    subject_points = min(raw_subj_points, 15)

    # 6. Body Text & HTML Security Analysis
    plain_text, html_text, html_urls, html_security_flags = extract_body_text_and_security(parsed_email)
    combined_body = (plain_text + " " + html_text).strip()

    # Heuristic NLP patterns in body
    body_indicators = extract_indicators(combined_body) if combined_body else []

    # Run SMS model as body-analysis proxy
    text_model, text_vectorizer = load_text_models()
    body_ml_prob = None
    body_ml_pred = "Heuristic Only"
    body_ml_points = 0

    if text_model is not None and text_vectorizer is not None and combined_body:
        try:
            X_vec = text_vectorizer.transform([combined_body])
            probs = text_model.predict_proba(X_vec)[0]
            # spam/malicious probability
            body_ml_prob = float(probs[1]) if len(probs) > 1 else float(probs[0])
            body_ml_pred = "Malicious/Spam" if body_ml_prob >= 0.50 else "Legitimate/Ham"
            body_ml_points = min(int(round(body_ml_prob * 30)), 30)
        except Exception as e:
            logger.warning(f"Error evaluating text model proxy on email body: {e}")
            raw_body_pts = sum(ind.get("severity_score", 5) for ind in body_indicators)
            body_ml_points = min(raw_body_pts, 20)
    else:
        # Fallback to heuristics if model offline
        raw_body_pts = sum(ind.get("severity_score", 5) for ind in body_indicators)
        body_ml_points = min(raw_body_pts, 20)

    # 7. URL Extraction & Cascaded Analysis
    extracted_urls = extract_urls_from_email(plain_text, html_urls)
    url_analyses: List[Dict[str, Any]] = []
    max_url_risk = 0

    for u in extracted_urls:
        try:
            # Reuses existing URL analyzer (which also checks Threat Intelligence if enabled)
            u_res = analyze_url(u)
            url_analyses.append(u_res)
            u_risk = int(u_res.get("risk_score", 0))
            if u_risk > max_url_risk:
                max_url_risk = u_risk
        except Exception as err:
            logger.warning(f"Error cascading URL '{u}' in email: {err}")

    # Scaled cascaded URL contribution (up to 20 points from highest risk URL)
    url_cascade_points = min(int(round(max_url_risk * 0.20)), 20)

    # 8. Attachment Metadata Analysis
    attachments, attachment_indicators, attachment_points = analyze_attachments(parsed_email)

    # 9. Calculate Centralized Composite Risk Score via risk_engine
    risk_data = calculate_email_risk(
        header_points=header_points,
        auth_points=auth_points,
        subject_points=subject_points,
        body_ml_points=body_ml_points,
        attachment_points=attachment_points,
        url_cascade_points=url_cascade_points,
        max_url_risk=max_url_risk,
        body_ml_prob=body_ml_prob
    )

    risk_score = risk_data.get("risk_score", 0)
    risk_level = risk_data.get("risk_level", "Low")
    prediction = "Phishing" if risk_score >= 55 else ("Suspicious" if risk_score >= 25 else "Legitimate")

    # 10. Assemble Phase 9 Explanation via explanation_builder
    explanation = build_email_explanation(
        parsed_email=parsed_email,
        header_indicators=header_indicators,
        auth_data=auth_data,
        subject_indicators=subject_indicators,
        body_indicators=body_indicators,
        body_ml_prob=body_ml_prob,
        body_ml_pred=body_ml_pred,
        attachments=attachments,
        attachment_indicators=attachment_indicators,
        url_analyses=url_analyses,
        html_security_flags=html_security_flags,
        risk_data=risk_data
    )

    # Assemble and return canonical API result envelope
    return {
        "success": True,
        "prediction": prediction,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "recommendation": risk_data.get("recommendation", ""),
        "email_analysis": {
            "headers": parsed_email.get("headers", {}),
            "domains": parsed_email.get("domains", {}),
            "authentication": {
                "has_auth_header": auth_data.get("has_auth_header", False),
                "spf": auth_data.get("spf"),
                "dkim": auth_data.get("dkim"),
                "dmarc": auth_data.get("dmarc"),
                "indicators": auth_indicators
            },
            "header_indicators": header_indicators,
            "subject_indicators": subject_indicators,
            "body_indicators": body_indicators,
            "body_ml_proxy": {
                "model": "TF-IDF + Logistic Regression (reused as body-analysis proxy)",
                "probability": round(body_ml_prob, 4) if body_ml_prob is not None else None,
                "prediction": body_ml_pred,
                "points_contributed": body_ml_points,
                "points_maximum": 30
            },
            "html_security_flags": html_security_flags,
            "extracted_urls": [
                {
                    "url": ua.get("normalized_url", ua.get("input_url", "")),
                    "risk_score": ua.get("risk_score", 0),
                    "risk_level": ua.get("risk_level", "Low"),
                    "prediction": ua.get("prediction", "Legitimate"),
                    "threat_intelligence": ua.get("threat_intelligence")
                }
                for ua in url_analyses
            ],
            "attachments": attachments,
            "attachment_indicators": attachment_indicators
        },
        "risk_breakdown": risk_data.get("calculation_breakdown", {}),
        "explanation": explanation
    }
