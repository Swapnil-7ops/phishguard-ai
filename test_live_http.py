import urllib.request

routes = [
    ('/', 'Home Page'),
    ('/dashboard', 'Dashboard Page'),
    ('/url-analyzer', 'URL Analyzer Page'),
    ('/message-analyzer', 'Message Analyzer Page'),
    ('/history', 'Scan History Page'),
    ('/model-performance', 'Model Performance Page'),
    ('/about', 'About Project Page'),
    ('/api/health', 'Health Check API'),
    ('/api/dashboard-stats', 'Dashboard Stats API'),
    ('/api/history', 'Scan History API'),
    ('/api/model-metrics', 'Model Metrics API')
]

print("=== Live HTTP Response Verification on http://127.0.0.1:5000 ===")
for path, name in routes:
    url = 'http://127.0.0.1:5000' + path
    try:
        with urllib.request.urlopen(url) as response:
            status = response.getcode()
            print(f"[OK 200] {name:<25} ({path})")
    except Exception as e:
        print(f"[FAILED] {name:<25} ({path}) -> {e}")
print("==================================================================")
