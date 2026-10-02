"""
run_tests.py - PhishGuard AI Unified Test Runner

Runs all unit and integration tests across tests/ directory without requiring third-party test runners.
"""
import sys
import inspect
import traceback
from pathlib import Path

_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(_ROOT))

from tests import (
    test_features, test_rules, test_risk_engine, test_api,
    test_ml_pipeline, test_database, test_text_model,
    test_url_regression, test_message_regression, test_model_loading_failure,
    test_explanation, test_qr, test_threat_intelligence,
    test_screenshot, test_email, test_phase14_integration,
)

TEST_MODULES = [
    ("URL Features", test_features),
    ("Cybersecurity Rules", test_rules),
    ("Risk Engine", test_risk_engine),
    ("Flask REST API", test_api),
    ("Phase 3 ML Pipeline", test_ml_pipeline),
    ("Phase 6 Database & History", test_database),
    ("Phase 7 Text ML Pipeline", test_text_model),
    # Phase 8 regression & hardening tests
    ("Phase 8 URL Regression", test_url_regression),
    ("Phase 8 Message Regression", test_message_regression),
    ("Phase 8 Model Loading Failure", test_model_loading_failure),
    # Phase 9 Explainable AI Investigation System
    ("Phase 9 Explainable AI", test_explanation),
    # Phase 10 QR / Quishing Detection
    ("Phase 10 QR / Quishing Detection", test_qr),
    # Phase 11 Threat Intelligence
    ("Phase 11 Threat Intelligence", test_threat_intelligence),
    # Phase 12 Screenshot / Visual Phishing Detection
    ("Phase 12 Screenshot Vision", test_screenshot),
    # Phase 13 Email Phishing Analysis (.EML)
    ("Phase 13 Email Analysis", test_email),
    # Phase 14 Final Integration & Security Hardening
    ("Phase 14 Final Integration", test_phase14_integration),
]


def run_all():
    print("=" * 70)
    print("       PHISHGUARD AI - AUTOMATED TEST SUITE")
    print("=" * 70)

    total = 0
    passed = 0
    failed = 0
    failures = []

    for mod_name, mod in TEST_MODULES:
        print(f"\n[{mod_name}]")
        for attr_name in dir(mod):
            if attr_name.startswith("test_") and callable(getattr(mod, attr_name)):
                fn = getattr(mod, attr_name)
                total += 1
                try:
                    fn()
                    passed += 1
                    print(f"  [PASS] {attr_name}")
                except Exception as e:
                    failed += 1
                    err_msg = f"{attr_name} failed: {e}\n{traceback.format_exc()}"
                    failures.append((mod_name, attr_name, err_msg))
                    print(f"  [FAIL] {attr_name} -> {e}")

    print("\n" + "=" * 70)
    print(f"RESULTS: Total={total} | PASSED={passed} | FAILED={failed}")
    print("=" * 70)

    if failures:
        print("\nFAILURE DETAILS:")
        for mod_name, test_name, err in failures:
            print(f"\n--- {mod_name} :: {test_name} ---")
            print(err)
        return 1

    return 0


if __name__ == '__main__':
    sys.exit(run_all())
