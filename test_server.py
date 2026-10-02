"""
test_server.py - Verification script to test that all required pages and routes load with HTTP 200.
"""
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(_ROOT))

from app import create_app

def verify_all_pages():
    app = create_app()
    app.config['TESTING'] = True
    client = app.test_client()

    pages = [
        ('/', 'Home page'),
        ('/dashboard', 'Dashboard page'),
        ('/url-analyzer', 'URL Analyzer page'),
        ('/message-analyzer', 'Message Analyzer page'),
        ('/history', 'Scan History page'),
        ('/model-performance', 'Model Performance page'),
        ('/about', 'About page'),
        ('/api/dashboard-stats', 'Dashboard Stats API'),
        ('/api/history', 'Scan History API'),
        ('/api/model-metrics', 'Model Metrics API'),
        ('/api/health', 'Health Check API')
    ]

    all_passed = True
    print("\n--- Verifying All Core Website Foundation Pages & Routes ---")
    for path, desc in pages:
        res = client.get(path)
        status = res.status_code
        if status == 200:
            print(f"[PASS] {desc:<25} ({path}) -> HTTP {status}")
        else:
            print(f"[FAIL] {desc:<25} ({path}) -> HTTP {status}")
            all_passed = False

    print("----------------------------------------------------------")
    if all_passed:
        print("ALL PAGES AND ROUTES VERIFIED SUCCESSFULLY (HTTP 200 OK)!")
    else:
        print("SOME ROUTES FAILED!")
        sys.exit(1)

if __name__ == '__main__':
    verify_all_pages()
