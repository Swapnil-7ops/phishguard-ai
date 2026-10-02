"""
generate_fixtures.py - Generator script for safe, local PhishGuard AI demo fixtures.

Creates:
1. demo_fixtures/screenshots/legitimate_login.png
2. demo_fixtures/screenshots/suspicious_login.png
3. demo_fixtures/qr/legitimate_qr.png
4. demo_fixtures/qr/suspicious_qr.png
5. demo_fixtures/qr/qr_payloads.txt
6. demo_fixtures/emails/legitimate_email.eml
7. demo_fixtures/emails/phishing_email.eml
8. demo_fixtures/emails/demo_attachment.txt
9. demo_fixtures/emails/email_with_attachment.eml
"""
import email.message
import email.policy
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
from pathlib import Path
import qrcode
from PIL import Image, ImageDraw, ImageFont

BASE_DIR = Path(__file__).resolve().parent
SCREENSHOT_DIR = BASE_DIR / "screenshots"
QR_DIR = BASE_DIR / "qr"
EMAIL_DIR = BASE_DIR / "emails"

for d in (SCREENSHOT_DIR, QR_DIR, EMAIL_DIR):
    d.mkdir(parents=True, exist_ok=True)


def get_font(size: int, bold: bool = False):
    """Load standard system font with fallback."""
    font_names = ["arialbd.ttf" if bold else "arial.ttf", "segoeui.ttf", "calibri.ttf"]
    for fn in font_names:
        try:
            return ImageFont.truetype(fn, size)
        except Exception:
            pass
    return ImageFont.load_default()


# ======================================================================
# 1. SCREENSHOT FIXTURES
# ======================================================================

def create_legitimate_screenshot():
    """Create a clean, fictional legitimate login page screenshot."""
    w, h = 800, 600
    img = Image.new("RGB", (w, h), color=(244, 246, 249))
    draw = ImageDraw.Draw(img)

    # Top navigation bar
    draw.rectangle([0, 0, w, 50], fill=(36, 72, 85))  # Deep teal
    title_font = get_font(20, bold=True)
    draw.text((25, 14), "PhishGuard Demo Portal", fill=(251, 233, 208), font=title_font)

    nav_font = get_font(13)
    draw.text((580, 18), "Documentation", fill=(200, 215, 220), font=nav_font)
    draw.text((690, 18), "Help Center", fill=(200, 215, 220), font=nav_font)

    # Centered card
    card_x0, card_y0, card_x1, card_y1 = 230, 95, 570, 520
    draw.rectangle([card_x0, card_y0, card_x1, card_y1], fill=(255, 255, 255), outline=(209, 213, 219), width=2)

    card_header_font = get_font(18, bold=True)
    draw.text((275, 125), "Sign In to Your Account", fill=(30, 41, 59), font=card_header_font)

    subtitle_font = get_font(12)
    draw.text((260, 155), "Fictional Demonstration System — Safe Environment", fill=(100, 116, 139), font=subtitle_font)

    # Form Fields
    lbl_font = get_font(12, bold=True)
    placeholder_font = get_font(13)

    # Email field
    draw.text((260, 195), "Email Address", fill=(51, 65, 85), font=lbl_font)
    draw.rectangle([260, 220, 540, 265], fill=(255, 255, 255), outline=(148, 163, 184), width=2)
    draw.text((275, 232), "user@example.com", fill=(148, 163, 184), font=placeholder_font)

    # Password field
    draw.text((260, 285), "Password", fill=(51, 65, 85), font=lbl_font)
    draw.rectangle([260, 310, 540, 355], fill=(255, 255, 255), outline=(148, 163, 184), width=2)
    draw.text((275, 322), "••••••••••••", fill=(148, 163, 184), font=placeholder_font)

    # Button
    draw.rectangle([260, 385, 540, 435], fill=(36, 72, 85), outline=(25, 50, 60), width=1)
    btn_font = get_font(14, bold=True)
    draw.text((370, 399), "Sign In", fill=(255, 255, 255), font=btn_font)

    # Secondary text
    note_font = get_font(11)
    draw.text((280, 460), "Authorized fictional personnel only.", fill=(148, 163, 184), font=note_font)
    draw.text((270, 480), "Never share credentials with third parties.", fill=(148, 163, 184), font=note_font)

    # Bottom notice
    draw.text((285, 555), "Demo Environment — For Evaluation Only", fill=(100, 116, 139), font=note_font)

    out_path = SCREENSHOT_DIR / "legitimate_login.png"
    img.save(out_path, format="PNG")
    print(f"Created: {out_path}")


def create_suspicious_screenshot():
    """Create a fictional phishing-style login screenshot with urgent warnings and domain mismatch."""
    w, h = 800, 600
    img = Image.new("RGB", (w, h), color=(254, 242, 242))
    draw = ImageDraw.Draw(img)

    # Urgent Warning Banner
    draw.rectangle([0, 0, w, 55], fill=(220, 38, 38))  # Alarming red
    warn_font = get_font(17, bold=True)
    draw.text((120, 16), "CRITICAL ALERT: ACCOUNT SUSPENSION IMMINENT", fill=(255, 255, 255), font=warn_font)

    # Sub-banner with fake domain notice
    draw.rectangle([0, 55, w, 88], fill=(254, 226, 226))
    domain_font = get_font(12, bold=True)
    draw.text((150, 65), "Verification Host: verify-account.example.test — Session Expires in 24 Hours", fill=(185, 28, 28), font=domain_font)

    # Main Card with red outline
    card_x0, card_y0, card_x1, card_y1 = 200, 105, 600, 560
    draw.rectangle([card_x0, card_y0, card_x1, card_y1], fill=(255, 255, 255), outline=(239, 68, 68), width=3)

    header_font = get_font(18, bold=True)
    draw.text((260, 125), "Secure Account Verification", fill=(185, 28, 28), font=header_font)

    alert_box_x0, alert_box_y0, alert_box_x1, alert_box_y1 = 220, 160, 580, 215
    draw.rectangle([alert_box_x0, alert_box_y0, alert_box_x1, alert_box_y1], fill=(255, 241, 242), outline=(244, 63, 94), width=1)
    urgency_font = get_font(11)
    draw.text((230, 168), "WARNING: Suspicious activity was detected on your account.", fill=(159, 18, 57), font=urgency_font)
    draw.text((230, 186), "Enter your credentials below immediately to confirm identity.", fill=(159, 18, 57), font=urgency_font)

    lbl_font = get_font(11, bold=True)
    ph_font = get_font(12)

    # Username Field
    draw.text((230, 228), "Username / Email Address", fill=(30, 41, 59), font=lbl_font)
    draw.rectangle([230, 248, 570, 288], fill=(255, 255, 255), outline=(220, 38, 38), width=2)
    draw.text((245, 258), "target.account@example.test", fill=(148, 163, 184), font=ph_font)

    # Password Field
    draw.text((230, 298), "Current Account Password", fill=(30, 41, 59), font=lbl_font)
    draw.rectangle([230, 318, 570, 358], fill=(255, 255, 255), outline=(220, 38, 38), width=2)
    draw.text((245, 328), "••••••••••••", fill=(148, 163, 184), font=ph_font)

    # One-Time Passcode Field
    draw.text((230, 368), "One-Time Verification Code (OTP)", fill=(30, 41, 59), font=lbl_font)
    draw.rectangle([230, 388, 570, 428], fill=(255, 255, 255), outline=(220, 38, 38), width=2)
    draw.text((245, 398), "Enter 6-digit OTP", fill=(148, 163, 184), font=ph_font)

    # Urgent Button
    draw.rectangle([230, 450, 570, 498], fill=(220, 38, 38), outline=(185, 28, 28), width=1)
    btn_font = get_font(14, bold=True)
    draw.text((320, 464), "VERIFY NOW (URGENT)", fill=(255, 255, 255), font=btn_font)

    footer_font = get_font(10)
    draw.text((240, 515), "Failure to verify within 24 hours results in permanent deactivation.", fill=(220, 38, 38), font=footer_font)
    draw.text((275, 532), "Action Server: verify-account.example.test", fill=(100, 116, 139), font=footer_font)

    # Bottom notice
    draw.text((290, 575), "Fictional Demonstration Phishing Artifact", fill=(150, 50, 50), font=footer_font)

    out_path = SCREENSHOT_DIR / "suspicious_login.png"
    img.save(out_path, format="PNG")
    print(f"Created: {out_path}")


# ======================================================================
# 2. QR FIXTURES
# ======================================================================

def create_qr_fixtures():
    """Create genuine machine-readable QR codes with fictional demo payloads."""
    payload_legit = "https://example.com/"
    payload_phish = "https://example.test/verify-account-login"

    # Legitimate QR
    qr_legit = qrcode.QRCode(version=1, box_size=10, border=4)
    qr_legit.add_data(payload_legit)
    qr_legit.make(fit=True)
    img_legit = qr_legit.make_image(fill_color="black", back_color="white")
    path_legit = QR_DIR / "legitimate_qr.png"
    img_legit.save(path_legit)
    print(f"Created: {path_legit}")

    # Suspicious QR
    qr_phish = qrcode.QRCode(version=1, box_size=10, border=4)
    qr_phish.add_data(payload_phish)
    qr_phish.make(fit=True)
    img_phish = qr_phish.make_image(fill_color="black", back_color="white")
    path_phish = QR_DIR / "suspicious_qr.png"
    img_phish.save(path_phish)
    print(f"Created: {path_phish}")

    # qr_payloads.txt
    payloads_txt = (
        "legitimate_qr.png\n"
        f"Payload: {payload_legit}\n\n"
        "suspicious_qr.png\n"
        f"Payload: {payload_phish}\n"
    )
    payload_file = QR_DIR / "qr_payloads.txt"
    payload_file.write_text(payloads_txt, encoding="utf-8")
    print(f"Created: {payload_file}")


# ======================================================================
# 3. EMAIL FIXTURES (.EML)
# ======================================================================

def create_email_fixtures():
    """Create RFC 5322 MIME .eml demo email files."""
    # A. Legitimate email
    legit_msg = email.message.EmailMessage()
    legit_msg["From"] = "support@example.com"
    legit_msg["To"] = "student@example.com"
    legit_msg["Subject"] = "Your Demo Account Information"
    legit_msg["Date"] = "Thu, 01 Oct 2026 10:00:00 +0000"
    legit_msg["Message-ID"] = "<demo-legit-001@example.com>"
    legit_msg["Authentication-Results"] = "mx.example.com; spf=pass (example.com); dkim=pass header.d=example.com; dmarc=pass"
    legit_msg.set_content(
        "Hello,\n\n"
        "This is a legitimate demonstration email for the PhishGuard AI project.\n\n"
        "Your demo account is active.\n\n"
        "Regards,\n"
        "Demo Support Team\n"
    )
    legit_path = EMAIL_DIR / "legitimate_email.eml"
    with open(legit_path, "wb") as f:
        f.write(legit_msg.as_bytes())
    print(f"Created: {legit_path}")

    # B. Phishing email
    phish_msg = email.message.EmailMessage()
    phish_msg["From"] = "security@example.test"
    phish_msg["Reply-To"] = "verify@example.test"
    phish_msg["To"] = "student@example.com"
    phish_msg["Subject"] = "Urgent Account Verification Required"
    phish_msg["Date"] = "Thu, 01 Oct 2026 10:15:00 +0000"
    phish_msg["Message-ID"] = "<demo-phish-002@example.test>"
    phish_msg["Authentication-Results"] = "mx.example.com; spf=softfail (example.test); dkim=fail; dmarc=fail"
    phish_msg.set_content(
        "Your account requires immediate verification.\n\n"
        "Please verify your account using the following demonstration URL:\n\n"
        "https://example.test/verify-account\n\n"
        "Failure to verify may result in account suspension.\n\n"
        "Regards,\n"
        "Demo Security Team\n"
    )
    phish_path = EMAIL_DIR / "phishing_email.eml"
    with open(phish_path, "wb") as f:
        f.write(phish_msg.as_bytes())
    print(f"Created: {phish_path}")

    # C. Harmless attachment file
    att_path = EMAIL_DIR / "demo_attachment.txt"
    att_path.write_text("This is a harmless demonstration attachment for PhishGuard AI.\n", encoding="utf-8")
    print(f"Created: {att_path}")

    # D. Email with harmless attachment fixture
    msg_with_att = MIMEMultipart()
    msg_with_att["From"] = "notifications@example.com"
    msg_with_att["To"] = "student@example.com"
    msg_with_att["Subject"] = "Demo Project Attachment Notice"
    msg_with_att["Date"] = "Thu, 01 Oct 2026 10:30:00 +0000"
    msg_with_att["Message-ID"] = "<demo-attach-003@example.com>"
    msg_with_att["Authentication-Results"] = "mx.example.com; spf=pass; dkim=pass; dmarc=pass"

    body_part = MIMEText("Hello,\n\nPlease find attached the harmless demo attachment for testing attachment metadata inspection.\n\nRegards,\nDemo Team", "plain")
    msg_with_att.attach(body_part)

    part = MIMEBase("text", "plain")
    part.set_payload(b"This is a harmless demonstration attachment for PhishGuard AI.\n")
    encoders.encode_base64(part)
    part.add_header("Content-Disposition", 'attachment; filename="demo_attachment.txt"')
    msg_with_att.attach(part)

    att_eml_path = EMAIL_DIR / "email_with_attachment.eml"
    with open(att_eml_path, "wb") as f:
        f.write(msg_with_att.as_bytes())
    print(f"Created: {att_eml_path}")


if __name__ == "__main__":
    create_legitimate_screenshot()
    create_suspicious_screenshot()
    create_qr_fixtures()
    create_email_fixtures()
    print("All fixtures generated successfully.")
