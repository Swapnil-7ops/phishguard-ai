"""
tests/test_email.py - Phase 13 Email Phishing Analysis (.EML) Test Suite

Comprehensive testing covering:
  1. File validation (extension, size, empty file, malformed structures)
  2. RFC 5322 and MIME email parsing (plain, HTML, multipart, attachments, encoded headers)
  3. Header forensics (Reply-To mismatch, Return-Path divergence, missing date/msgid, display spoofing)
  4. Authentication analysis (SPF pass/fail/softfail, DKIM pass/fail, DMARC pass/fail, absent headers)
  5. Subject social engineering inspection (urgency, credentials, suspension, financial)
  6. Body linguistic analysis & TF-IDF + Logistic Regression text proxy integration
  7. Embedded URL extraction, deduplication, and URL risk cascade
  8. Attachment metadata forensics (executables, scripts, macros, archives, double extensions, path traversal)
  9. Security safeguards (HTML script/iframe injection, javascript: links, zero execution, zero URL fetching)
 10. Risk engine composite scoring, bounded point allocations, and clamping
 11. Structured Phase 9 explanation and dynamic investigation timeline
 12. Persistence integration (save_scan with scan_type='email')
 13. REST API endpoint contract (/api/analyze-email)
"""

import io
import os
import sys
from email.message import EmailMessage
from unittest.mock import patch, MagicMock

import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from services.email_service import (
    validate_eml_file,
    parse_eml,
    analyze_headers,
    analyze_authentication,
    analyze_subject,
    extract_body_text_and_security,
    extract_urls_from_email,
    analyze_attachments,
    process_email_analysis,
)
from services.risk_engine import calculate_email_risk
from services.explanation_builder import build_email_explanation
from database.mongodb import save_scan
from app import create_app


# ─────────────────────────────────────────────────────────────────────────────
# Synthetic In-Memory EML Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _make_eml_bytes(
    from_addr: str = "security@company.com",
    to_addr: str = "employee@company.com",
    subject: str = "Quarterly All-Hands Meeting",
    plain_text: str = "Please find the agenda attached for tomorrow's meeting.",
    html_text: str = None,
    reply_to: str = None,
    return_path: str = None,
    auth_results: str = None,
    date: str = "Wed, 01 Oct 2026 10:00:00 +0000",
    message_id: str = "<12345@company.com>",
    attachments: list = None
) -> bytes:
    """Construct standard RFC 5322 MIME message bytes in memory."""
    msg = EmailMessage()
    msg['From'] = from_addr
    msg['To'] = to_addr
    msg['Subject'] = subject
    if date:
        msg['Date'] = date
    if message_id:
        msg['Message-ID'] = message_id
    if reply_to:
        msg['Reply-To'] = reply_to
    if return_path:
        msg['Return-Path'] = return_path
    if auth_results:
        msg['Authentication-Results'] = auth_results

    if html_text and plain_text:
        msg.set_content(plain_text)
        msg.add_alternative(html_text, subtype='html')
    elif html_text:
        msg.set_content(html_text, subtype='html')
    else:
        msg.set_content(plain_text)

    if attachments:
        for att in attachments:
            fname = att.get('filename', 'attachment.dat')
            data = att.get('data', b'dummy content')
            maintype = att.get('maintype', 'application')
            subtype = att.get('subtype', 'octet-stream')
            msg.add_attachment(data, maintype=maintype, subtype=subtype, filename=fname)

    return msg.as_bytes()


def _get_test_client():
    app = create_app()
    app.config["TESTING"] = True
    return app.test_client()


# ─────────────────────────────────────────────────────────────────────────────
# 1. File Validation Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_validate_valid_eml():
    b = _make_eml_bytes()
    # Should complete without raising
    validate_eml_file(b, "message.eml")


def test_validate_empty_bytes():
    with pytest.raises(ValueError, match="empty"):
        validate_eml_file(b"", "message.eml")


def test_validate_oversized_bytes():
    big_bytes = b"X" * (11 * 1024 * 1024)
    with pytest.raises(ValueError, match="exceeds maximum"):
        validate_eml_file(big_bytes, "big.eml")


def test_validate_unsupported_extension():
    b = _make_eml_bytes()
    with pytest.raises(ValueError, match="Unsupported file extension"):
        validate_eml_file(b, "document.pdf")


def test_validate_malformed_non_email():
    with pytest.raises(ValueError):
        validate_eml_file(b"\x00\x01\x02\x03\x04\x05", "corrupt.eml")


# ─────────────────────────────────────────────────────────────────────────────
# 2. Email Parsing Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_parse_simple_plain_text():
    b = _make_eml_bytes(
        from_addr="Alice <alice@test.com>",
        to_addr="Bob <bob@test.com>",
        subject="Hello",
        plain_text="This is a simple plain text email."
    )
    res = parse_eml(b)
    assert res["domains"]["sender_domain"] == "test.com"
    assert "Hello" in res["headers"]["subject"]
    assert "simple plain text" in res["body"]["plain_text"]
    assert len(res["attachments"]) == 0


def test_parse_multipart_plain_and_html():
    b = _make_eml_bytes(
        plain_text="Plain fallback text.",
        html_text="<p>HTML <strong>rich</strong> text.</p>"
    )
    res = parse_eml(b)
    assert "Plain fallback" in res["body"]["plain_text"]
    assert "<strong>rich</strong>" in res["body"]["html"]


def test_parse_encoded_subject():
    b = b"""From: sender@domain.com\r\nTo: dest@domain.com\r\nSubject: =?utf-8?B?QWNjb3VudCBBbGVydCE=?=\r\nDate: Wed, 01 Oct 2026 10:00:00 +0000\r\nMessage-ID: <1@domain.com>\r\n\r\nTest content"""
    res = parse_eml(b)
    assert "Account Alert!" in res["headers"]["subject"]


def test_parse_missing_headers_graceful():
    b = b"""From: sender@minimal.com\r\n\r\nBody with no other headers"""
    res = parse_eml(b)
    assert res["domains"]["sender_domain"] == "minimal.com"
    assert res["headers"]["subject"] == ""
    assert res["headers"]["reply_to"] == ""
    assert res["headers"]["date"] == ""
    assert res["headers"]["message_id"] == ""


def test_parse_multiple_recipients():
    b = _make_eml_bytes(to_addr="one@test.com, two@test.com")
    res = parse_eml(b)
    assert "one@test.com" in res["headers"]["to"]
    assert "two@test.com" in res["headers"]["to"]


# ─────────────────────────────────────────────────────────────────────────────
# 3. Header Analysis Forensics
# ─────────────────────────────────────────────────────────────────────────────

def test_headers_reply_to_mismatch():
    b = _make_eml_bytes(
        from_addr="support@trusted-bank.com",
        reply_to="support@trusted-bank-security.net"
    )
    parsed = parse_eml(b)
    indicators = analyze_headers(parsed)
    ind_ids = [i["id"] for i in indicators]
    assert "HDR_REPLYTO_MISMATCH" in ind_ids


def test_headers_reply_to_match_no_indicator():
    b = _make_eml_bytes(
        from_addr="support@trusted-bank.com",
        reply_to="helpdesk@trusted-bank.com"
    )
    parsed = parse_eml(b)
    indicators = analyze_headers(parsed)
    ind_ids = [i["id"] for i in indicators]
    assert "HDR_REPLYTO_MISMATCH" not in ind_ids


def test_headers_return_path_divergence():
    b = _make_eml_bytes(
        from_addr="notifications@mycompany.org",
        return_path="bounce@attacker-relay.com"
    )
    parsed = parse_eml(b)
    indicators = analyze_headers(parsed)
    ind_ids = [i["id"] for i in indicators]
    assert "HDR_RETURNPATH_MISMATCH" in ind_ids


def test_headers_missing_date_and_msgid():
    b = b"""From: bot@spammer.com\r\nSubject: Test\r\n\r\nHello world"""
    parsed = parse_eml(b)
    indicators = analyze_headers(parsed)
    ind_ids = [i["id"] for i in indicators]
    assert "HDR_MISSING_DATE" in ind_ids
    assert "HDR_MISSING_MSGID" in ind_ids


def test_headers_multiple_at_in_sender():
    b = _make_eml_bytes(from_addr="admin@paypal.com@evildomain.com")
    parsed = parse_eml(b)
    indicators = analyze_headers(parsed)
    ind_ids = [i["id"] for i in indicators]
    assert "HDR_MULTIPLE_AT" in ind_ids


# ─────────────────────────────────────────────────────────────────────────────
# 4. Authentication Forensics (SPF, DKIM, DMARC)
# ─────────────────────────────────────────────────────────────────────────────

def test_auth_all_pass():
    b = _make_eml_bytes(
        auth_results="mx.google.com; dkim=pass header.i=@company.com; spf=pass (google.com: domain of user@company.com designates 1.2.3.4 as permitted sender); dmarc=pass"
    )
    parsed = parse_eml(b)
    auth = analyze_authentication(parsed)
    assert auth["spf"] == "pass"
    assert auth["dkim"] == "pass"
    assert auth["dmarc"] == "pass"
    assert auth["auth_points"] == 0
    assert len(auth["indicators"]) == 0


def test_auth_dmarc_fail():
    b = _make_eml_bytes(
        auth_results="mail.corp.com; dmarc=fail (p=reject sp=reject) header.from=paypal.com; spf=fail; dkim=fail"
    )
    parsed = parse_eml(b)
    auth = analyze_authentication(parsed)
    assert auth["dmarc"] == "fail"
    assert auth["spf"] == "fail"
    assert auth["dkim"] == "fail"
    ind_ids = [i["id"] for i in auth["indicators"]]
    assert "AUTH_DMARC_FAIL" in ind_ids
    assert "AUTH_SPF_FAIL" in ind_ids
    assert "AUTH_DKIM_FAIL" in ind_ids
    assert auth["auth_points"] > 0


def test_auth_spf_softfail():
    b = _make_eml_bytes(auth_results="mail.server.net; spf=softfail (sender IP not explicitly permitted)")
    parsed = parse_eml(b)
    auth = analyze_authentication(parsed)
    assert auth["spf"] == "softfail"
    ind_ids = [i["id"] for i in auth["indicators"]]
    assert "AUTH_SPF_SOFTFAIL" in ind_ids


def test_auth_header_absent():
    b = _make_eml_bytes()
    parsed = parse_eml(b)
    auth = analyze_authentication(parsed)
    assert auth["has_auth_header"] is False
    assert auth["spf"] == "not_present"
    assert auth["auth_points"] == 0
    assert len(auth["indicators"]) == 0


# ─────────────────────────────────────────────────────────────────────────────
# 5. Subject Social Engineering Analysis
# ─────────────────────────────────────────────────────────────────────────────

def test_subject_urgency_flagged():
    inds = analyze_subject("URGENT: Immediate action required on your account")
    ind_ids = [i["id"] for i in inds]
    assert "SUBJ_URGENCY" in ind_ids


def test_subject_suspension_flagged():
    inds = analyze_subject("Security Alert: Your account will be suspended")
    ind_ids = [i["id"] for i in inds]
    assert "SUBJ_SUSPENSION" in ind_ids


def test_subject_credential_flagged():
    inds = analyze_subject("Please verify your password immediately")
    ind_ids = [i["id"] for i in inds]
    assert "SUBJ_CREDENTIAL" in ind_ids


def test_subject_financial_flagged():
    inds = analyze_subject("Invoice payment declined - refund pending")
    ind_ids = [i["id"] for i in inds]
    assert "SUBJ_FINANCIAL" in ind_ids


def test_subject_benign():
    inds = analyze_subject("Weekly team sync notes - Oct 1")
    assert len(inds) == 0


# ─────────────────────────────────────────────────────────────────────────────
# 6. Body Analysis & Classifier Proxy
# ─────────────────────────────────────────────────────────────────────────────

def test_body_safe_text_extraction():
    b = _make_eml_bytes(
        plain_text="Text version here.",
        html_text="<html><body><h1>Welcome</h1><p>Visit us at <a href='https://example.com/login'>here</a>.</p></body></html>"
    )
    parsed = parse_eml(b)
    plain, html_vis, urls, flags = extract_body_text_and_security(parsed)
    assert "Text version" in plain
    assert "Welcome" in html_vis
    assert "https://example.com/login" in urls
    assert len(flags) == 0


def test_body_ml_proxy_evaluation():
    # Verify process_email_analysis runs body text through text model proxy safely
    b = _make_eml_bytes(plain_text="URGENT: Your account credentials have expired. Verify your password immediately.")
    with patch("services.email_service.analyze_url") as mock_url:
        res = process_email_analysis(b, "urgent.eml")
    assert "body_ml_proxy" in res["email_analysis"]
    proxy = res["email_analysis"]["body_ml_proxy"]
    assert "model" in proxy
    assert "points_contributed" in proxy
    assert proxy["points_maximum"] == 30


# ─────────────────────────────────────────────────────────────────────────────
# 7. URL Extraction & Cascaded Analysis
# ─────────────────────────────────────────────────────────────────────────────

def test_url_extraction_plain_and_html():
    plain = "Check out https://plain-link.org/test for details."
    html_urls = ["https://html-link.com/click", "https://plain-link.org/test"]  # duplicate
    urls = extract_urls_from_email(plain, html_urls)
    assert len(urls) == 2
    assert "https://plain-link.org/test" in urls
    assert "https://html-link.com/click" in urls


def test_multiple_urls_cascades_highest_risk():
    b = _make_eml_bytes(plain_text="Link 1: https://safe-site.com Link 2: https://evil-phish.net")
    mock_safe = {
        "success": True,
        "normalized_url": "https://safe-site.com",
        "risk_score": 10,
        "risk_level": "Low",
        "prediction": "Legitimate",
        "threat_intelligence": None
    }
    mock_evil = {
        "success": True,
        "normalized_url": "https://evil-phish.net",
        "risk_score": 90,
        "risk_level": "Critical",
        "prediction": "Phishing",
        "threat_intelligence": None
    }

    def side_effect(u):
        return mock_evil if "evil" in u else mock_safe

    with patch("services.email_service.analyze_url", side_effect=side_effect):
        res = process_email_analysis(b, "multi_url.eml")

    # URL cascade must be min(round(90 * 0.20), 20) = 18 points (NOT 10+90)
    bd = res["risk_breakdown"]
    assert bd["max_url_risk_raw"] == 90
    assert bd["url_cascade_points"] == 18
    assert bd["url_cascade_max"] == 20


# ─────────────────────────────────────────────────────────────────────────────
# 8. Attachment Metadata Forensics
# ─────────────────────────────────────────────────────────────────────────────

def test_attachment_benign_pdf():
    b = _make_eml_bytes(
        attachments=[{"filename": "contract.pdf", "data": b"%PDF-1.4 test", "maintype": "application", "subtype": "pdf"}]
    )
    parsed = parse_eml(b)
    inspected, indicators, points = analyze_attachments(parsed)
    assert len(inspected) == 1
    assert inspected[0]["extension"] == ".pdf"
    assert inspected[0]["risk_category"] == "benign"
    assert points == 0


def test_attachment_executable_flagged():
    b = _make_eml_bytes(
        attachments=[{"filename": "invoice_update.exe", "data": b"MZ...", "maintype": "application", "subtype": "octet-stream"}]
    )
    parsed = parse_eml(b)
    inspected, indicators, points = analyze_attachments(parsed)
    ind_ids = [i["id"] for i in indicators]
    assert "ATT_EXECUTABLE" in ind_ids
    assert points > 0


def test_attachment_double_extension():
    b = _make_eml_bytes(
        attachments=[{"filename": "statement.pdf.exe", "data": b"MZ...", "maintype": "application", "subtype": "octet-stream"}]
    )
    parsed = parse_eml(b)
    inspected, indicators, points = analyze_attachments(parsed)
    ind_ids = [i["id"] for i in indicators]
    assert "ATT_DOUBLE_EXTENSION" in ind_ids


def test_attachment_path_traversal():
    b = _make_eml_bytes(
        attachments=[{"filename": "../../etc/passwd", "data": b"root:x:0:0", "maintype": "text", "subtype": "plain"}]
    )
    parsed = parse_eml(b)
    inspected, indicators, points = analyze_attachments(parsed)
    ind_ids = [i["id"] for i in indicators]
    assert "ATT_PATH_TRAVERSAL" in ind_ids


def test_attachment_script_and_macro():
    b = _make_eml_bytes(
        attachments=[
            {"filename": "macro.docm", "data": b"docm content"},
            {"filename": "payload.vbs", "data": b"msgbox 1"}
        ]
    )
    parsed = parse_eml(b)
    inspected, indicators, points = analyze_attachments(parsed)
    ind_ids = [i["id"] for i in indicators]
    assert "ATT_MACRO" in ind_ids
    assert "ATT_SCRIPT" in ind_ids


# ─────────────────────────────────────────────────────────────────────────────
# 9. Security & HTML Safeguards
# ─────────────────────────────────────────────────────────────────────────────

def test_security_html_script_tag_detected():
    b = _make_eml_bytes(html_text="<p>Hello</p><script>alert('XSS')</script>")
    parsed = parse_eml(b)
    plain, html_vis, urls, flags = extract_body_text_and_security(parsed)
    flag_types = [f["type"] for f in flags]
    assert "SCRIPT_TAG_INJECTION" in flag_types
    # Script tag body must NOT appear in visible extracted text
    assert "alert" not in html_vis


def test_security_html_iframe_detected():
    b = _make_eml_bytes(html_text="<iframe src='http://attacker.com'></iframe>")
    parsed = parse_eml(b)
    plain, html_vis, urls, flags = extract_body_text_and_security(parsed)
    flag_types = [f["type"] for f in flags]
    assert "IFRAME_INJECTION" in flag_types


def test_security_javascript_uri_flagged():
    b = _make_eml_bytes(html_text="<a href='javascript:stealCookies()'>Click Here</a>")
    parsed = parse_eml(b)
    plain, html_vis, urls, flags = extract_body_text_and_security(parsed)
    flag_types = [f["type"] for f in flags]
    assert "JAVASCRIPT_URI" in flag_types
    # javascript: scheme must not be in extracted clean HTTP URLs
    assert not any(u.startswith('javascript:') for u in urls)


def test_security_inline_event_handler_flagged():
    b = _make_eml_bytes(html_text="<div onclick='doEvil()'>Click here for prize</div>")
    parsed = parse_eml(b)
    plain, html_vis, urls, flags = extract_body_text_and_security(parsed)
    flag_types = [f["type"] for f in flags]
    assert "INLINE_EVENT_HANDLER" in flag_types


def test_security_no_network_requests_to_target():
    """Verify that email analysis never makes outbound HTTP requests to extracted links."""
    b = _make_eml_bytes(plain_text="Visit https://never-contact-this-host.org")
    with patch("urllib.request.urlopen") as mock_urllib, \
         patch("requests.get") as mock_req_get, \
         patch("requests.post") as mock_req_post:
        # Mock URL analyzer so no network is attempted
        with patch("services.email_service.analyze_url") as mock_analyze:
            mock_analyze.return_value = {
                "success": True, "risk_score": 10, "risk_level": "Low", "prediction": "Legitimate"
            }
            res = process_email_analysis(b, "test.eml")

        assert mock_urllib.call_count == 0
        assert mock_req_get.call_count == 0
        assert mock_req_post.call_count == 0


# ─────────────────────────────────────────────────────────────────────────────
# 10. Risk Engine Point Allocation & Clamping
# ─────────────────────────────────────────────────────────────────────────────

def test_risk_engine_all_zero():
    res = calculate_email_risk(0, 0, 0, 0, 0, 0)
    assert res["risk_score"] == 0
    assert res["risk_level"] == "Low"


def test_risk_engine_clamping_to_100():
    # Provide maximum points: 20 + 20 + 15 + 30 + 15 + 20 = 120 points
    res = calculate_email_risk(
        header_points=50,   # exceeds 20
        auth_points=50,     # exceeds 20
        subject_points=50,  # exceeds 15
        body_ml_points=50,  # exceeds 30
        attachment_points=50, # exceeds 15
        url_cascade_points=50 # exceeds 20
    )
    bd = res["calculation_breakdown"]
    assert bd["header_points"] == 20
    assert bd["auth_points"] == 20
    assert bd["subject_points"] == 15
    assert bd["body_ml_points"] == 30
    assert bd["attachment_points"] == 15
    assert bd["url_cascade_points"] == 20
    assert bd["raw_point_sum"] == 120
    # Strictly clamped to 100
    assert res["risk_score"] == 100
    assert res["risk_level"] == "Critical"


def test_risk_engine_partial_scoring():
    res = calculate_email_risk(
        header_points=10,
        auth_points=7,
        subject_points=5,
        body_ml_points=12,
        attachment_points=0,
        url_cascade_points=6
    )
    # 10 + 7 + 5 + 12 + 0 + 6 = 40
    assert res["risk_score"] == 40
    assert res["risk_level"] == "Medium"


# ─────────────────────────────────────────────────────────────────────────────
# 11. Explanation Generation & Dynamic Timeline
# ─────────────────────────────────────────────────────────────────────────────

def test_explanation_structure_and_timeline():
    b = _make_eml_bytes(
        from_addr="billing@fake-portal.com",
        reply_to="stealer@attacker.net",
        subject="URGENT: Payment failed",
        plain_text="Click here https://fake-portal.com/login",
        auth_results="mail.server; spf=fail; dmarc=fail",
        attachments=[{"filename": "statement.exe", "data": b"MZ"}]
    )
    with patch("services.email_service.analyze_url") as mock_url:
        mock_url.return_value = {
            "success": True,
            "normalized_url": "https://fake-portal.com/login",
            "risk_score": 85,
            "risk_level": "Critical",
            "prediction": "Phishing"
        }
        res = process_email_analysis(b, "sample.eml")

    exp = res["explanation"]
    assert "summary" in exp
    assert "header_evidence" in exp
    assert "auth_evidence" in exp
    assert "subject_evidence" in exp
    assert "body_evidence" in exp
    assert "attachment_evidence" in exp
    assert "url_evidence" in exp
    assert "risk_contribution" in exp
    assert "investigation_stages" in exp
    assert exp["scan_type"] == "email"

    stage_names = [s["stage"] for s in exp["investigation_stages"]]
    assert "Header Forensics" in stage_names
    assert "Authentication Analysis" in stage_names
    assert "URL Extraction & Cascade Analysis" in stage_names
    assert "Attachment Metadata Inspection" in stage_names
    assert "Composite Risk Calculation" in stage_names


# ─────────────────────────────────────────────────────────────────────────────
# 12. Persistence Layer Integration
# ─────────────────────────────────────────────────────────────────────────────

def test_database_persistence_email():
    b = _make_eml_bytes(subject="Database Save Test")
    with patch("services.email_service.analyze_url") as mock_url:
        mock_url.return_value = {"success": True, "risk_score": 0, "prediction": "Legitimate"}
        result = process_email_analysis(b, "test_save.eml")

    scan_id = save_scan(
        input_type="email",
        raw_input="[Email: test_save.eml - Database Save Test]",
        analysis_result=result
    )
    assert scan_id is not None
    assert len(scan_id) > 10


# ─────────────────────────────────────────────────────────────────────────────
# 13. REST API Endpoint Tests (/api/analyze-email)
# ─────────────────────────────────────────────────────────────────────────────

def test_api_analyze_email_success(client=None):
    c = client or _get_test_client()
    b = _make_eml_bytes()
    data = {
        "file": (io.BytesIO(b), "test.eml")
    }
    with patch("services.email_service.analyze_url") as mock_url:
        mock_url.return_value = {"success": True, "risk_score": 0, "prediction": "Legitimate"}
        res = c.post("/api/analyze-email", data=data, content_type="multipart/form-data")

    assert res.status_code == 200
    json_data = res.get_json()
    assert json_data["success"] is True
    assert "data" in json_data
    assert "risk_score" in json_data["data"]
    assert "email_analysis" in json_data["data"]
    assert "explanation" in json_data["data"]
    assert "scan_id" in json_data["data"]


def test_api_analyze_email_missing_field(client=None):
    c = client or _get_test_client()
    res = c.post("/api/analyze-email", data={}, content_type="multipart/form-data")
    assert res.status_code == 400
    assert res.get_json()["success"] is False


def test_api_analyze_email_empty_filename(client=None):
    c = client or _get_test_client()
    data = {"file": (io.BytesIO(b""), "")}
    res = c.post("/api/analyze-email", data=data, content_type="multipart/form-data")
    assert res.status_code == 400
    assert res.get_json()["success"] is False


def test_api_analyze_email_disallowed_extension(client=None):
    c = client or _get_test_client()
    data = {"file": (io.BytesIO(b"hello"), "message.txt")}
    res = c.post("/api/analyze-email", data=data, content_type="multipart/form-data")
    assert res.status_code == 400
    assert res.get_json()["success"] is False


def test_api_analyze_email_corrupt_file(client=None):
    c = client or _get_test_client()
    data = {"file": (io.BytesIO(b""), "message.eml")}
    res = c.post("/api/analyze-email", data=data, content_type="multipart/form-data")
    assert res.status_code == 400
    assert res.get_json()["success"] is False
