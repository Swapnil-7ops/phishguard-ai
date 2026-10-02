import sys
import email
from pathlib import Path
from PIL import Image
import cv2

base = Path(__file__).resolve().parent
project_root = base.parent
sys.path.insert(0, str(project_root))

# 1. Validate Screenshots
s1 = base / 'screenshots' / 'legitimate_login.png'
s2 = base / 'screenshots' / 'suspicious_login.png'
assert s1.exists() and s2.exists(), 'Screenshots missing'

img1 = Image.open(s1)
img1.verify()
img1 = Image.open(s1)
assert img1.size == (800, 600) and img1.format == 'PNG', 'Invalid legitimate screenshot'

img2 = Image.open(s2)
img2.verify()
img2 = Image.open(s2)
assert img2.size == (800, 600) and img2.format == 'PNG', 'Invalid suspicious screenshot'
print('Validation 1: Both PNG screenshot fixtures open and verify successfully (800x600 PNG).')

# 2. Validate QR Codes and Payloads
qr1 = base / 'qr' / 'legitimate_qr.png'
qr2 = base / 'qr' / 'suspicious_qr.png'
assert qr1.exists() and qr2.exists(), 'QR files missing'

detector = cv2.QRCodeDetector()

cv_qr1 = cv2.imread(str(qr1))
val1, _, _ = detector.detectAndDecode(cv_qr1)
assert val1 == 'https://example.com/', f'QR1 payload mismatch: {val1}'

cv_qr2 = cv2.imread(str(qr2))
val2, _, _ = detector.detectAndDecode(cv_qr2)
assert val2 == 'https://example.test/verify-account-login', f'QR2 payload mismatch: {val2}'

payloads_file = base / 'qr' / 'qr_payloads.txt'
assert payloads_file.exists(), 'qr_payloads.txt missing'
assert 'https://example.com/' in payloads_file.read_text(encoding='utf-8')
assert 'https://example.test/verify-account-login' in payloads_file.read_text(encoding='utf-8')
print('Validation 2: Both QR codes decode cleanly via cv2.QRCodeDetector:')
print(f'  - legitimate_qr.png -> {val1}')
print(f'  - suspicious_qr.png -> {val2}')

# 3. Validate Email Files (.eml)
eml1 = base / 'emails' / 'legitimate_email.eml'
eml2 = base / 'emails' / 'phishing_email.eml'
eml3 = base / 'emails' / 'email_with_attachment.eml'
att_txt = base / 'emails' / 'demo_attachment.txt'

assert eml1.exists() and eml2.exists() and eml3.exists() and att_txt.exists(), 'Email fixtures missing'

import email.policy
from services.email_service import parse_eml

with open(eml1, 'rb') as f:
    eml1_bytes = f.read()
    msg1 = email.message_from_bytes(eml1_bytes, policy=email.policy.default)
assert msg1['Subject'] == 'Your Demo Account Information'
assert msg1['From'] == 'support@example.com'
parse_res1 = parse_eml(eml1_bytes)
assert parse_res1['headers']['subject'] == 'Your Demo Account Information'

with open(eml2, 'rb') as f:
    eml2_bytes = f.read()
    msg2 = email.message_from_bytes(eml2_bytes, policy=email.policy.default)
assert msg2['Subject'] == 'Urgent Account Verification Required'
assert msg2['From'] == 'security@example.test'
assert msg2['Reply-To'] == 'verify@example.test'
parse_res2 = parse_eml(eml2_bytes)
assert parse_res2['headers']['subject'] == 'Urgent Account Verification Required'

with open(eml3, 'rb') as f:
    eml3_bytes = f.read()
    msg3 = email.message_from_bytes(eml3_bytes, policy=email.policy.default)
assert msg3['Subject'] == 'Demo Project Attachment Notice'
attachments = [p.get_filename() for p in msg3.iter_attachments()]
assert 'demo_attachment.txt' in attachments
parse_res3 = parse_eml(eml3_bytes)
assert any(att['filename'] == 'demo_attachment.txt' for att in parse_res3['attachments'])

print('Validation 3: All .eml email fixtures parsed successfully using stdlib email parser & PhishGuard parse_eml:')
print(f'  - legitimate_email.eml: Subject = "{msg1["Subject"]}"')
print(f'  - phishing_email.eml: Subject = "{msg2["Subject"]}"')
print(f'  - email_with_attachment.eml: Attachment = {attachments}')

# 4. Validate README
readme = base / 'README.md'
assert readme.exists(), 'README.md missing'
readme_content = readme.read_text(encoding='utf-8')
assert 'legitimate_login.png' in readme_content
assert 'suspicious_login.png' in readme_content
assert 'legitimate_qr.png' in readme_content
assert 'suspicious_qr.png' in readme_content
assert 'legitimate_email.eml' in readme_content
assert 'phishing_email.eml' in readme_content
print('Validation 4: README.md exists and accurately references all fixtures.')
print('ALL VALIDATIONS PASSED CLEANLY.')
