"""
feature_descriptions.py - Human-Readable URL Feature Observation Layer

WHAT: Maps each of the 25 lexical URL features to a human-readable sentence
      and an observation level (normal / noteworthy / suspicious).
WHY:  Provides an evidence-based explanation layer for the URL analysis
      without fabricating causal model attribution.
IMPORTANT:
  - These are OBSERVATIONS of extracted structural properties.
  - They do NOT claim that a feature CAUSED the model's classification.
  - HTTPS is noted as encrypted transport only; it does NOT imply legitimacy.
"""

from typing import Dict, Any, Tuple

# Each entry: (observation_sentence, level)
# level: "normal" | "noteworthy" | "suspicious"

FEATURE_DESCRIPTIONS = {
    "url_length": {
        "normal_threshold": 75,
        "suspicious_threshold": 120,
        "format": lambda v: (
            f"URL length is {v} characters, which falls within a normal range."
            if v <= 75 else
            (f"URL length is {v} characters — elevated length detected."
             if v <= 120 else
             f"URL length is {v} characters — unusually long URLs are often used to obscure the domain."),
            "normal" if v <= 75 else ("noteworthy" if v <= 120 else "suspicious")
        )
    },
    "hostname_length": {
        "format": lambda v: (
            f"Hostname length is {v} characters.",
            "normal" if v <= 30 else ("noteworthy" if v <= 50 else "suspicious")
        )
    },
    "path_length": {
        "format": lambda v: (
            f"URL path length is {v} characters.",
            "normal" if v <= 50 else ("noteworthy" if v <= 100 else "suspicious")
        )
    },
    "query_length": {
        "format": lambda v: (
            f"Query string length is {v} characters." if v > 0 else "No query string is present.",
            "normal" if v <= 50 else ("noteworthy" if v <= 100 else "suspicious")
        )
    },
    "num_dots": {
        "format": lambda v: (
            f"{v} dot(s) detected in the URL structure.",
            "normal" if v <= 3 else ("noteworthy" if v <= 5 else "suspicious")
        )
    },
    "num_hyphens": {
        "format": lambda v: (
            f"{v} hyphen(s) detected — phishers often concatenate brand names with security buzzwords using hyphens."
            if v >= 3 else f"{v} hyphen(s) detected.",
            "normal" if v < 3 else ("noteworthy" if v < 5 else "suspicious")
        )
    },
    "num_underscores": {
        "format": lambda v: (
            f"{v} underscore(s) detected in the URL.",
            "normal" if v == 0 else "noteworthy"
        )
    },
    "num_slashes": {
        "format": lambda v: (
            f"{v} slash(es) detected in the URL.",
            "normal" if v <= 4 else "noteworthy"
        )
    },
    "num_question_marks": {
        "format": lambda v: (
            f"{v} question mark(s) detected — query parameter delimiter.",
            "normal" if v <= 1 else "noteworthy"
        )
    },
    "num_equal_signs": {
        "format": lambda v: (
            f"{v} equal sign(s) detected — query parameter values present.",
            "normal" if v <= 3 else "noteworthy"
        )
    },
    "num_ampersands": {
        "format": lambda v: (
            f"{v} ampersand(s) detected — multiple query parameters chained.",
            "normal" if v <= 3 else "noteworthy"
        )
    },
    "num_percent": {
        "format": lambda v: (
            f"{v} percent character(s) detected — may indicate percent-encoding obfuscation."
            if v >= 2 else f"{v} percent character(s) detected.",
            "normal" if v < 2 else ("noteworthy" if v < 5 else "suspicious")
        )
    },
    "has_at_symbol": {
        "format": lambda v: (
            "An @ symbol was detected. Browsers treat everything before @ as credentials and silently route requests to the host specified after @, potentially redirecting the user to a malicious destination."
            if v == 1 else "No @ symbol detected.",
            "suspicious" if v == 1 else "normal"
        )
    },
    "has_ip_address": {
        "format": lambda v: (
            "The URL uses a raw IP address instead of a conventional domain name. Legitimate services virtually always use registered domain names."
            if v == 1 else "The hostname is a conventional domain name (not a raw IP address).",
            "suspicious" if v == 1 else "normal"
        )
    },
    "uses_https": {
        "format": lambda v: (
            "HTTPS is enabled, indicating encrypted transport. Note: HTTPS confirms encryption only — it does NOT establish that the website is legitimate or trustworthy."
            if v == 1 else "Plain HTTP (unencrypted) transport is in use. This does not prove malicious intent, but is unsafe for transmitting credentials.",
            "normal" if v == 1 else "noteworthy"
        )
    },
    "num_subdomains": {
        "format": lambda v: (
            f"{v} subdomain level(s) detected." if v <= 1 else
            (f"{v} subdomain levels detected — elevated subdomain nesting observed."
             if v == 2 else
             f"{v} subdomain levels detected — deep subdomain chaining is frequently used in brand-spoofing attacks (e.g., login.paypal.com.attacker.xyz)."),
            "normal" if v <= 1 else ("noteworthy" if v == 2 else "suspicious")
        )
    },
    "suspicious_keyword_count": {
        "format": lambda v: (
            f"{v} credential-related keyword(s) detected (e.g., login, verify, account, secure, banking)."
            if v > 0 else "No credential-related keywords detected in the URL.",
            "normal" if v == 0 else ("noteworthy" if v == 1 else "suspicious")
        )
    },
    "is_url_shortener": {
        "format": lambda v: (
            "A URL shortening service was detected. URL shorteners obscure the actual destination from user inspection."
            if v == 1 else "No URL shortening service detected.",
            "suspicious" if v == 1 else "normal"
        )
    },
    "hostname_entropy": {
        "format": lambda v: (
            f"Hostname Shannon entropy is {v:.2f} — normal range."
            if v <= 3.5 else
            (f"Hostname Shannon entropy is {v:.2f} — elevated. High entropy may indicate an algorithmically generated or randomized domain."
             if v <= 3.75 else
             f"Hostname Shannon entropy is {v:.2f} — high. Consistent with algorithmically generated or disposable domain names (DGA)."),
            "normal" if v <= 3.5 else ("noteworthy" if v <= 3.75 else "suspicious")
        )
    },
    "digit_count": {
        "format": lambda v: (
            f"{v} numeric digit(s) in the URL."
            if v < 8 else
            f"{v} numeric digits in the URL — high digit count may indicate randomized campaign tokens or automated URL generation.",
            "normal" if v < 8 else "noteworthy"
        )
    },
    "special_char_count": {
        "format": lambda v: (
            f"{v} non-standard special character(s) detected." if v > 0 else "No non-standard special characters detected.",
            "normal" if v == 0 else ("noteworthy" if v <= 2 else "suspicious")
        )
    },
    "domain_path_ratio": {
        "format": lambda v: (
            f"Domain-to-path length ratio is {v:.2f}.",
            "normal" if 0 <= v <= 3 else "noteworthy"
        )
    },
    "has_suspicious_tld": {
        "format": lambda v: (
            "The domain uses a TLD statistically associated with disposable or abusive registrations (e.g., .tk, .xyz, .top, .ml)."
            if v == 1 else "The TLD is not classified as high-risk by the project rule set.",
            "suspicious" if v == 1 else "normal"
        )
    },
    "encoded_char_count": {
        "format": lambda v: (
            f"{v} percent-encoded sequence(s) detected (%XX). Heavy encoding can be used to conceal IP addresses or path components from simple string filters."
            if v >= 2 else (f"{v} percent-encoded sequence(s) detected." if v > 0 else "No percent-encoded sequences detected."),
            "normal" if v < 2 else ("noteworthy" if v < 5 else "suspicious")
        )
    },
    "has_double_slash_path": {
        "format": lambda v: (
            "A double slash (//) was detected in the URL path (beyond the protocol separator). This can trigger protocol-relative redirect vulnerabilities."
            if v == 1 else "No double slash anomaly detected in the URL path.",
            "suspicious" if v == 1 else "normal"
        )
    },
}


def describe_feature(name: str, value: Any) -> Tuple[str, str]:
    """
    Return a (sentence, observation_level) tuple for a single feature.

    Args:
        name: Feature name (one of the 25 canonical names).
        value: The raw feature value.

    Returns:
        Tuple of (human_readable_sentence, level) where level is
        'normal', 'noteworthy', or 'suspicious'.
        Falls back to a generic description if feature is unknown.
    """
    entry = FEATURE_DESCRIPTIONS.get(name)
    if entry is None:
        return f"{name}: {value}", "normal"
    try:
        result = entry["format"](value)
        return result[0], result[1]
    except Exception:
        return f"{name}: {value}", "normal"


def describe_all_features(features: Dict[str, Any]) -> list:
    """
    Build a full feature evidence list from a features dict.

    Returns:
        List of dicts with keys: name, value, sentence, level.
    """
    evidence = []
    for name, value in features.items():
        sentence, level = describe_feature(name, value)
        evidence.append({
            "name": name,
            "value": value,
            "sentence": sentence,
            "level": level
        })
    return evidence

