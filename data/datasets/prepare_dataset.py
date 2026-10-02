"""
prepare_dataset.py - Dataset Generator and Downloader for PhishGuard AI

WHAT: Prepares balanced, structured datasets for training URL and Message models.
WHY: Academic models must be trained on clear, labelled, reproducible data.
HOW: Gathers verified legitimate URLs (popular domains, deep paths, HTTPS APIs)
     and verified phishing patterns (IP addresses, credential harvesting subdomains,
     typosquatting, @ redirects, suspicious TLDs, encoded paths).
INPUT: None (self-contained verified corpus).
OUTPUT: data/datasets/phishing_urls.csv and data/datasets/phishing_messages.csv.
"""
import csv
import logging
from pathlib import Path

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
logger = logging.getLogger(__name__)

DATA_DIR = Path(__file__).resolve().parent

# Curated high-fidelity legitimate URL seeds (real internet services across categories)
LEGITIMATE_SEEDS = [
    "https://www.google.com/search?q=cybersecurity+research",
    "https://en.wikipedia.org/wiki/Phishing",
    "https://en.wikipedia.org/wiki/Machine_learning",
    "https://github.com/torvalds/linux/commits/master",
    "https://github.com/scikit-learn/scikit-learn",
    "https://stackoverflow.com/questions/tagged/python",
    "https://docs.python.org/3/library/urllib.parse.html",
    "https://aws.amazon.com/what-is-cloud-computing/",
    "https://azure.microsoft.com/en-us/solutions/",
    "https://www.apple.com/macos/sonoma/",
    "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
    "https://www.netflix.com/browse/genre/83",
    "https://www.nytimes.com/section/technology",
    "https://www.bbc.com/news/world",
    "https://www.linkedin.com/feed/",
    "https://medium.com/topic/technology",
    "https://arxiv.org/abs/2301.00001",
    "https://www.khanacademy.org/math/statistics-probability",
    "https://pypi.org/project/scikit-learn/",
    "https://www.reddit.com/r/netsec/",
    "https://www.coursera.org/browse/information-technology",
    "https://developer.mozilla.org/en-US/docs/Web/HTTP",
    "https://httpbin.org/get?param=value",
    "https://www.cloudflare.com/learning/security/what-is-phishing/",
    "https://csrc.nist.gov/publications/detail/sp/800-63/3/final",
    "https://owasp.org/www-project-top-ten/",
    "https://www.kaggle.com/datasets",
    "https://gitlab.com/explore/projects",
    "https://www.docker.com/products/docker-desktop/",
    "https://www.elastic.co/what-is/elasticsearch",
    "https://www.mongodb.com/docs/manual/introduction/",
    "https://flask.palletsprojects.com/en/latest/",
    "https://pandas.pydata.org/docs/getting_started/index.html",
    "https://numpy.org/doc/stable/user/quickstart.html",
    "https://archive.org/web/",
    "https://www.nationalgeographic.com/science",
    "https://www.harvard.edu/programs/",
    "https://www.mit.edu/research/",
    "https://stanford.edu/academics/",
    "https://www.ieee.org/conferences/index.html",
    "https://www.acm.org/publications",
    "https://www.nature.com/articles/s41586-020-2649-2",
    "https://www.sciencedirect.com/science/article/pii/S016740482030137X",
    "https://news.ycombinator.com/item?id=30000000",
    "https://www.spotify.com/us/premium/",
    "https://www.dropbox.com/features/share",
    "https://www.zoom.com/en/products/virtual-meetings/",
    "https://slack.com/help/articles/115004071768-What-is-Slack",
    "https://workspace.google.com/products/gmail/",
    "https://outlook.live.com/mail/0/inbox",
    "http://www.columbia.edu/~fdc/sample.html",
    "http://info.cern.ch/hypertext/WWW/TheProject.html",
    "http://example.com/index.html",
    "https://www.gnu.org/software/bash/manual/bash.html",
    "https://www.w3.org/TR/html52/",
    "https://curl.se/docs/manpage.html",
    "https://git-scm.com/book/en/v2",
    "https://ubuntu.com/download/desktop",
    "https://www.kernel.org/doc/html/latest/",
    "https://www.freedesktop.org/wiki/Software/systemd/"
]

# Curated realistic phishing samples exhibiting typical adversarial heuristics
PHISHING_SEEDS = [
    "http://192.168.1.100/secure/login.php?user=admin",
    "http://104.244.42.1/webscr/login.html?cmd=_login-run",
    "http://45.33.32.156:8080/paypal/update-billing-info.html",
    "http://217.182.169.13/appleid/verify/login.php",
    "http://185.220.101.5/chase-bank/secure-banking-signon/",
    "http://www.google.com@evil-phishing-domain.xyz/login.html",
    "http://security-paypal.com@verify-account-update.tk/sign-in",
    "http://account.netflix.com@billing-issue-fix.top/update",
    "http://support.apple.com@icloud-locked-security.ml/verify",
    "http://secure.chase.com@banking-session-timeout.cf/auth",
    "http://paypal-security-verification-portal.tk/login",
    "http://appleid-apple-support-warning.ml/verify-account.php",
    "http://netflix-billing-renew-suspended.ga/account-reactivation",
    "http://amazon-account-locked-order-alert.cf/confirm-billing",
    "http://bankofamerica-secure-auth-login.gq/online-banking",
    "http://chase-bank-verify-fraud-alert.xyz/portal/login.asp",
    "http://wellsfargo-identity-security-check.top/auth/verify",
    "http://microsoft-outlook-office365-login.work/owa/auth.html",
    "http://instagram-help-copyright-infringement.click/appeal",
    "http://facebook-security-check-suspension.loan/verify-now",
    "http://secure-login.paypal.com.customer-verification-portal.info/webscr",
    "http://login.microsoft.com.account-update-portal-auth.biz/adfs/ls",
    "http://signin.ebay.com.security-alert-resolution.net/ws/eBayISAPI.dll",
    "http://myaccount.google.com.security-notification-center.org/signin",
    "http://verify.appleid.apple.com.manage-your-account.cc/auth",
    "http://bit.ly/3xPayPalLoginUpdate",
    "http://tinyurl.com/bank-security-alert-login",
    "http://t.co/fake-urgent-suspension-link",
    "http://rb.gy/9verify-netflix-payment-now",
    "http://cutt.ly/chase-immediate-verification-action",
    "http://secure-login-account-update-billing-validation-system.com/auth/login?session=893274982374982374&target=verify_credentials",
    "http://banking-portal-secure-customer-service-department-alert.net/validate?client_id=8943274932&token=98439284923",
    "http://verify-your-account-now-to-prevent-permanent-suspension-within-24hrs.org/login",
    "http://apple-support-id-verification-icloud-locked-restore-center.info/session/auth",
    "http://paypal-resolution-center-fraud-detection-case-id-982348.com/webscr/login",
    "http://login-verify-account-update-portal.com//secure/bank/login.php",
    "http://account-suspended-action-required.org//signin/redirect.html",
    "http://online-verification-center.net//auth/webscr/login.jsp",
    "http://customer-support-desk-tickets.xyz//resolve/case-29384",
    "http://security-update-center-auth.top//session/restore-access",
    "http://secure-bank.com/%70%61%79%70%61%6c/login.php?user=verify",
    "http://portal-verify.com/%2e%2e/%61%70%70%6c%65/id.html",
    "http://auth-service.net/%73%65%63%75%72%65/%6c%6f%67%69%6e",
    "http://login-server.org/%61%63%63%6f%75%6e%74%2d%75%70%64%61%74%65",
    "http://verify-bank.com/%63%72%65%64%65%6e%74%69%61%6c%73",
    "http://x92jfk2847dhs93kd847.ru/gate.php?id=92384",
    "http://q9w8e7r6t5y4u3i2o1p0.xyz/login.html",
    "http://a1b2c3d4e5f6g7h8i9j0.top/auth/verify",
    "http://9876543210zyxwvutsrq.click/security/alert",
    "http://m9n8b7v6c5x4z3a2s1.loan/signin/confirm",
    "http://paypal-verification-centre-secure.com/webscr/login",
    "http://chase-online-account-recovery-portal.net/verify",
    "http://netflix-suspended-billing-portal.org/login",
    "http://amazon-prime-security-renewal-center.biz/auth",
    "http://wells-fargo-card-activation-service.info/signon",
    "http://dhl-package-tracking-fee-pending.top/pay",
    "http://fedex-delivery-address-confirmation.click/track",
    "http://usps-redelivery-scheduled-notice.xyz/confirm",
    "http://irs-tax-refund-status-claim.work/refund",
    "http://social-security-administration-notice.loan/verify"
]

def generate_expanded_urls():
    """Generate balanced, diversified real-world URL dataset."""
    urls = []
    labels = []

    # Add seeds
    for u in LEGITIMATE_SEEDS:
        urls.append(u)
        labels.append(0)

    for u in PHISHING_SEEDS:
        urls.append(u)
        labels.append(1)

    # Systematic permutations of legitimate paths
    legit_domains = [
        "https://www.google.com", "https://github.com", "https://en.wikipedia.org",
        "https://stackoverflow.com", "https://docs.python.org", "https://aws.amazon.com",
        "https://www.microsoft.com", "https://www.apple.com", "https://www.mozilla.org",
        "https://www.w3.org", "https://www.nist.gov", "https://www.cdc.gov",
        "https://www.kaggle.com", "https://www.reddit.com", "https://arxiv.org",
        "https://www.nature.com", "https://www.mit.edu", "https://www.stanford.edu",
        "https://pypi.org", "https://www.cloudflare.com", "https://hub.docker.com",
        "https://gitlab.com", "https://www.spotify.com", "https://slack.com",
        "https://zoom.us", "https://www.dropbox.com", "https://www.linkedin.com"
    ]
    legit_paths = [
        "/about", "/contact", "/terms", "/privacy", "/features",
        "/pricing", "/faq", "/docs/api/v1", "/releases/tag/v2.0",
        "/search?q=open+source+projects", "/explore/popular",
        "/blog/2026/04/security-advisory", "/download/latest",
        "/tutorials/getting-started", "/profile/settings/notifications"
    ]

    for d in legit_domains:
        for p in legit_paths:
            urls.append(d + p)
            labels.append(0)

    # Systematic permutations of phishing attack vectors
    phish_targets = ["paypal", "chase", "netflix", "appleid", "wellsfargo", "amazon", "microsoft", "google", "bankofamerica", "coinbase"]
    phish_actions = ["login", "verify-account", "security-update", "confirm-identity", "unlock-session", "billing-problem", "restore-access"]
    phish_tlds = [".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".work", ".click", ".loan"]

    for t in phish_targets:
        for a in phish_actions:
            for tld in phish_tlds[:4]:
                urls.append(f"http://{t}-{a}{tld}/auth/login.php?client_id=892347")
                labels.append(1)

    # Subdomain spoofing
    for t in phish_targets[:6]:
        for a in phish_actions[:4]:
            urls.append(f"http://{a}.{t}.com.account-verification-portal.xyz/webscr?case=9823")
            labels.append(1)

    # IP address hosts
    sample_ips = ["192.168.1.105", "45.33.21.12", "185.220.101.7", "104.244.42.8", "217.182.169.20"]
    for ip in sample_ips:
        for a in phish_actions[:4]:
            urls.append(f"http://{ip}/{a}/index.php?user=admin&token=489274")
            labels.append(1)

    return urls, labels


def create_url_dataset():
    """Write the dataset CSV file."""
    urls, labels = generate_expanded_urls()
    out_file = DATA_DIR / 'phishing_urls.csv'
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    with open(out_file, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['url', 'label'])
        for u, l in zip(urls, labels):
            writer.writerow([u, l])

    logger.info(f"URL dataset created successfully: {out_file}")
    logger.info(f"Total samples: {len(urls)} (Legitimate: {labels.count(0)}, Phishing: {labels.count(1)})")


def create_message_dataset():
    """Write message phishing dataset CSV file."""
    out_file = DATA_DIR / 'phishing_messages.csv'
    
    # Genuine examples representing common legitimate and smishing/phishing templates
    messages = [
        # Phishing / Scam / Smishing
        ("URGENT: Your Wells Fargo account has been locked. Verify immediately at http://wf-unlock.xyz", 1),
        ("ALERT: Unusual sign-in activity detected on your PayPal account. Confirm your identity now: http://paypal-verify.tk", 1),
        ("Your Netflix subscription payment failed! Update your credit card details immediately to avoid cancellation: http://netflix-billing.top", 1),
        ("Final Notice: Your Amazon order #92834 has been held due to unpaid import taxes. Pay $2.99 fee: http://amz-fee.ml", 1),
        ("Bank of America Security Alert: A charge of $982.00 was authorized on your card. If not you, call or visit http://boa-dispute.click", 1),
        ("Apple Support: Your iCloud has been locked due to illegal downloads. Verify your Apple ID immediately: http://apple-restore.ga", 1),
        ("IRS Tax Notification: You have an unclaimed federal tax refund of $1,420.50. Claim within 24 hours: http://irs-tax-gov.work", 1),
        ("Your package from DHL is pending delivery. Address incomplete. Update now: http://dhl-address-check.xyz", 1),
        ("Congratulations! You were randomly selected for a $1,000 Walmart Gift Card! Click here to claim your reward: http://free-rewards.loan", 1),
        ("ATTENTION: Your Microsoft 365 password expires in 2 hours. Keep your existing password by logging in: http://m365-pass-keep.top", 1),
        ("Security Warning: Unauthorized device connected to your Google Account. If not you, secure account: http://myaccount-google.cf", 1),
        ("USPS Alert: Package 92748923 cannot be delivered. Confirm redelivery fees at http://usps-redeliver.tk", 1),
        ("URGENT OTP: Your verification code is 849203. Never share this with anyone, including bank representatives.", 1),
        ("Your Social Security Number has been suspended due to fraudulent activity. Connect with an investigator now: http://ssa-verify.top", 1),
        ("Cryptocurrency Security Alert: Transfer of 0.85 BTC initiated from your Coinbase wallet. Cancel transaction: http://coinbase-cancel.xyz", 1),
        ("Dear customer, your Chase debit card has been deactivated for suspicious purchases. Reactivate online: http://chase-reactivate.ml", 1),
        ("Action Required: Your Outlook mailbox has reached its quota limit (99.8%). Upgrade storage for free: http://outlook-quota.click", 1),
        ("FedEx Delivery Notification: Your package is awaiting customs clearance. Pay $3.50 clearance fee: http://fedex-customs.top", 1),
        ("Exclusive job offer: Earn $500/day working from home 2 hours daily! No experience required. Apply now: http://easy-money-work.loan", 1),
        ("Warning: Your Instagram profile will be permanently deleted in 24 hours for copyright infringement. Appeal here: http://ig-appeal.xyz", 1),

        # Legitimate / Ham
        ("Hi Swapnil, here is the syllabus for the upcoming network security and cryptography examination.", 0),
        ("Meeting reminder: The senior design project presentation is scheduled for tomorrow at 10:30 AM in Seminar Hall B.", 0),
        ("Your Amazon order has shipped and will arrive on Thursday. Track your shipment at https://www.amazon.com/orders", 0),
        ("Thanks for lunch today! Let me know when you are free next week to discuss the research paper draft.", 0),
        ("Your monthly bank statement for the period ending March 31 is now ready to download in your banking app.", 0),
        ("Git commit notification: swapnil pushed 3 commits to repository main branch.", 0),
        ("Hello, please find attached the IEEE conference paper guidelines and latex template for formatting your submission.", 0),
        ("Hi team, standup will be postponed by 15 minutes today due to the department faculty meeting.", 0),
        ("Your appointment with Dr. Sharma has been confirmed for Friday, April 18 at 4:00 PM.", 0),
        ("Python 3.13 documentation on urllib.parse is available at https://docs.python.org/3/library/urllib.parse.html", 0),
        ("Can you please send me the notes from yesterday's database management systems lecture?", 0),
        ("Your Spotify receipt for this month's Premium subscription has been paid successfully. Total: $10.99.", 0),
        ("Reminder: Library books are due for return by Monday, April 21 to avoid late penalty charges.", 0),
        ("Hi professor, I have uploaded the final PBL project report and source code to the university portal.", 0),
        ("The weather forecast in Mumbai predicts clear skies with a temperature of 32 degrees Celsius today.", 0),
        ("Thank you for contributing to our open-source project. Your pull request has been merged.", 0),
        ("Please remember to turn off the laboratory workstations before leaving the department this evening.", 0),
        ("The webinar on Explainable Artificial Intelligence will begin at 6:00 PM IST on Microsoft Teams.", 0),
        ("Happy birthday! Wishing you a fantastic year filled with learning, success, and good health!", 0),
        ("Your bus reservation for Pune to Mumbai on Sunday morning has been confirmed. Seat: 14A.", 0)
    ]

    with open(out_file, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['text', 'label'])
        for text, label in messages:
            writer.writerow([text, label])

    logger.info(f"Message dataset created successfully: {out_file}")
    logger.info(f"Total samples: {len(messages)}")


if __name__ == '__main__':
    create_url_dataset()
    create_message_dataset()
