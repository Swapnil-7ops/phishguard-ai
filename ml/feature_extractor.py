"""
feature_extractor.py - URL Feature Extraction Module

WHAT: Extracts 25 deterministic numerical features from a given URL string.
WHY: Supervised machine learning algorithms (Random Forest) require structured numerical
     feature vectors to identify non-linear patterns characteristic of phishing domains.
HOW: Uses urllib.parse, regular expressions, tldextract, and Shannon entropy calculations.
INPUT: Raw or normalized URL string (str).
OUTPUT: Dict mapping feature name (str) -> numerical value (int/float).
LIMITATIONS:
  - Lexical analysis cannot inspect web page content or dynamic redirects.
  - Does not execute HTTP network requests to avoid Server-Side Request Forgery (SSRF).
  - Novel obfuscation techniques may produce lower signal.
"""
import re
import math
from urllib.parse import urlparse
from typing import Dict, Any, List

try:
    import tldextract
    _HAS_TLDEXTRACT = True
except ImportError:
    _HAS_TLDEXTRACT = False

# 25 Phishing keyword markers (context-aware search in full URL & hostname)
SUSPICIOUS_KEYWORDS: List[str] = [
    'login', 'signin', 'verify', 'verification', 'account', 'update',
    'secure', 'security', 'banking', 'bank', 'paypal', 'password',
    'credential', 'confirm', 'billing', 'wallet', 'support', 'alert',
    'suspended', 'unlock', 'validate', 'authenticate', 'service',
    'recover', 'webscr'
]

# Known URL shortener hostnames
URL_SHORTENERS: set = {
    'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd',
    'buff.ly', 'adf.ly', 'bit.do', 'rb.gy', 'cutt.ly', 'shorturl.at',
    'qr.net', 'tiny.cc', 'bc.vc', 'v.gd', 'shorte.st'
}

# TLDs historically prevalent in disposable/phishing registrations
SUSPICIOUS_TLDS: set = {
    'tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top', 'work', 'click',
    'loan', 'fit', 'cn', 'ru', 'link', 'buzz', 'surf', 'support',
    'live', 'icu', 'rest', 'monster', 'hair'
}

# The ordered 25 canonical feature names
FEATURE_NAMES: List[str] = [
    'url_length',
    'hostname_length',
    'path_length',
    'query_length',
    'num_dots',
    'num_hyphens',
    'num_underscores',
    'num_slashes',
    'num_question_marks',
    'num_equal_signs',
    'num_ampersands',
    'num_percent',
    'has_at_symbol',
    'has_ip_address',
    'uses_https',
    'num_subdomains',
    'suspicious_keyword_count',
    'is_url_shortener',
    'hostname_entropy',
    'digit_count',
    'special_char_count',
    'domain_path_ratio',
    'has_suspicious_tld',
    'encoded_char_count',
    'has_double_slash_path'
]


def calculate_entropy(text: str) -> float:
    """
    Calculate the Shannon Entropy of a string: H(X) = -sum(p * log2(p)).
    Higher entropy indicates random/algorithmically generated domain names (DGA).
    """
    if not text:
        return 0.0
    length = len(text)
    freq = {}
    for char in text:
        freq[char] = freq.get(char, 0) + 1
    entropy = 0.0
    for count in freq.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return round(entropy, 4)


def is_ip_address(hostname: str) -> int:
    """
    Detect whether the hostname is an IPv4 or IPv6 address.
    Phishing attacks frequently host sites directly on exposed IPs to bypass DNS blacklists.
    """
    if not hostname:
        return 0
    # Clean brackets for IPv6
    clean_host = hostname.strip('[]')
    # IPv4 regex match
    ipv4_pattern = r'^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$'
    if re.match(ipv4_pattern, clean_host):
        return 1
    # Hex or octal encoded IP forms
    if re.match(r'^(?:0x[0-9a-fA-F]+\.){3}0x[0-9a-fA-F]+$', clean_host):
        return 1
    # IPv6 format
    if ':' in clean_host and any(c in '0123456789abcdefABCDEF' for c in clean_host):
        return 1
    return 0


def extract_url_features(url: str) -> Dict[str, Any]:
    """
    Extract 25 deterministic numerical features from a URL.

    Args:
        url: Raw or normalized URL string.

    Returns:
        Dict mapping feature names to numerical scalar values (int or float).
    """
    if not url or not isinstance(url, str):
        return {k: 0 for k in FEATURE_NAMES}

    url_str = url.strip()

    # Prepend scheme if missing for uniform parsing
    if not re.match(r'^[a-zA-Z][a-zA-Z0-9+-.]*://', url_str):
        parse_target = 'http://' + url_str
    else:
        parse_target = url_str

    try:
        parsed = urlparse(parse_target)
    except Exception:
        return {k: 0 for k in FEATURE_NAMES}

    hostname = (parsed.hostname or '').lower()
    path = parsed.path or ''
    query = parsed.query or ''
    scheme = parsed.scheme.lower()

    # Extract subdomain and TLD using tldextract when available
    subdomain = ''
    suffix = ''
    if _HAS_TLDEXTRACT and hostname:
        try:
            ext = tldextract.extract(url_str)
            subdomain = ext.subdomain
            suffix = ext.suffix.lower()
        except Exception:
            pass

    if not suffix and '.' in hostname:
        parts = hostname.split('.')
        suffix = parts[-1]
        if len(parts) > 2:
            subdomain = '.'.join(parts[:-2])

    url_lower = url_str.lower()

    # 1. url_length
    f_url_length = len(url_str)

    # 2. hostname_length
    f_hostname_length = len(hostname)

    # 3. path_length
    f_path_length = len(path)

    # 4. query_length
    f_query_length = len(query)

    # 5. number of dots
    f_num_dots = url_str.count('.')

    # 6. number of hyphens
    f_num_hyphens = url_str.count('-')

    # 7. number of underscores
    f_num_underscores = url_str.count('_')

    # 8. number of slashes
    f_num_slashes = url_str.count('/')

    # 9. number of question marks
    f_num_question_marks = url_str.count('?')

    # 10. number of equal signs
    f_num_equal_signs = url_str.count('=')

    # 11. number of ampersands
    f_num_ampersands = url_str.count('&')

    # 12. number of percent signs
    f_num_percent = url_str.count('%')

    # 13. presence of @
    f_has_at = 1 if '@' in url_str else 0

    # 14. presence of IP address
    f_has_ip = is_ip_address(hostname)

    # 15. HTTPS usage
    f_uses_https = 1 if scheme == 'https' else 0

    # 16. number of subdomains
    if subdomain:
        f_num_subdomains = len([s for s in subdomain.split('.') if s])
    else:
        # Heuristic fallback based on hostname dot count minus standard domain parts
        dot_count = hostname.count('.')
        f_num_subdomains = max(0, dot_count - 1) if not f_has_ip else 0

    # 17. suspicious keyword count
    f_keyword_count = sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in url_lower)

    # 18. presence of URL shortening indicators
    f_is_shortener = 1 if hostname in URL_SHORTENERS or any(hostname.endswith('.' + s) for s in URL_SHORTENERS) else 0

    # 19. hostname entropy
    f_hostname_entropy = calculate_entropy(hostname)

    # 20. digit count in URL
    f_digit_count = sum(1 for c in url_str if c.isdigit())

    # 21. special-character count (non-alphanumeric excluding basic URL delimiters)
    special_chars = re.findall(r'[!$*+,;=\[\]{}|\\^`<>"\']', url_str)
    f_special_count = len(special_chars)

    # 22. domain/path ratio: len(path) / max(1, len(hostname))
    f_domain_path_ratio = round(len(path) / max(1, len(hostname)), 4)

    # 23. suspicious TLD indicator
    tld_check = suffix.split('.')[-1] if suffix else (hostname.split('.')[-1] if '.' in hostname else '')
    f_has_suspicious_tld = 1 if tld_check in SUSPICIOUS_TLDS else 0

    # 24. encoded-character indicator
    encoded_matches = re.findall(r'%[0-9a-fA-F]{2}', url_str)
    f_encoded_count = len(encoded_matches)

    # 25. double-slash path indicator (beyond protocol separator)
    after_proto = url_str
    if '://' in after_proto:
        after_proto = after_proto.split('://', 1)[1]
    f_has_double_slash_path = 1 if '//' in after_proto else 0

    return {
        'url_length': f_url_length,
        'hostname_length': f_hostname_length,
        'path_length': f_path_length,
        'query_length': f_query_length,
        'num_dots': f_num_dots,
        'num_hyphens': f_num_hyphens,
        'num_underscores': f_num_underscores,
        'num_slashes': f_num_slashes,
        'num_question_marks': f_num_question_marks,
        'num_equal_signs': f_num_equal_signs,
        'num_ampersands': f_num_ampersands,
        'num_percent': f_num_percent,
        'has_at_symbol': f_has_at,
        'has_ip_address': f_has_ip,
        'uses_https': f_uses_https,
        'num_subdomains': f_num_subdomains,
        'suspicious_keyword_count': f_keyword_count,
        'is_url_shortener': f_is_shortener,
        'hostname_entropy': f_hostname_entropy,
        'digit_count': f_digit_count,
        'special_char_count': f_special_count,
        'domain_path_ratio': f_domain_path_ratio,
        'has_suspicious_tld': f_has_suspicious_tld,
        'encoded_char_count': f_encoded_count,
        'has_double_slash_path': f_has_double_slash_path
    }


def get_feature_names() -> List[str]:
    """Return the ordered list of the 25 feature names."""
    return list(FEATURE_NAMES)
