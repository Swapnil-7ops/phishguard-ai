"""
app.py - PhishGuard AI Flask Application Factory and Server Entrypoint

Academic PBL Project: Explainable AI-Based Multi-Modal Phishing Detection System
Architecture:
  - Frontend: HTML5, CSS3, Vanilla JS, Chart.js
  - Backend: Python Flask REST API
  - Machine Learning: scikit-learn RandomForestClassifier (URL), TF-IDF + LogisticRegression (Text)
  - Rules: Deterministic cybersecurity heuristic indicators
  - Persistence: MongoDB (with transparent in-memory fallback)
  - Multimodal: QR code quishing decoder, screenshot vision inspector, optional LLM explainability
"""
import os
import logging
from flask import Flask, render_template, redirect, url_for

from config import config
from database.mongodb import init_database
from routes.url_routes import url_bp
from routes.message_routes import message_bp
from routes.scan_routes import scan_bp
from routes.dashboard_routes import dashboard_bp

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s'
)
logger = logging.getLogger("phishguard")


def create_app() -> Flask:
    """Initialize and configure the Flask web application."""
    app = Flask(__name__)
    app.secret_key = config.SECRET_KEY
    app.config['MAX_CONTENT_LENGTH'] = config.MAX_CONTENT_LENGTH

    # Ensure required runtime directories exist
    config.ensure_dirs()

    # Initialize Persistence
    init_database()

    # Register API Blueprints under /api prefix
    app.register_blueprint(url_bp, url_prefix='/api')
    app.register_blueprint(message_bp, url_prefix='/api')
    app.register_blueprint(scan_bp, url_prefix='/api')
    app.register_blueprint(dashboard_bp, url_prefix='/api')

    # Web UI Page Routes
    @app.route('/')
    def index():
        return render_template('index.html')

    @app.route('/dashboard')
    def view_dashboard():
        return render_template('dashboard.html')

    @app.route('/url-analyzer')
    def view_url_analyzer():
        return render_template('url_analyzer.html')

    @app.route('/message-analyzer')
    def view_message_analyzer():
        return render_template('message_analyzer.html')

    @app.route('/qr-scanner')
    def view_qr_scanner():
        return render_template('qr_scanner.html')

    @app.route('/screenshot-analyzer')
    def view_screenshot_analyzer():
        return render_template('screenshot_analyzer.html')

    @app.route('/email-analyzer')
    def view_email_analyzer():
        return render_template('email_analyzer.html')

    @app.route('/history')
    def view_history():
        return render_template('history.html')

    @app.route('/model-performance')
    def view_model_performance():
        return render_template('model_performance.html')

    @app.route('/about')
    def view_about():
        return render_template('about.html')

    logger.info("PhishGuard AI Flask application successfully instantiated.")
    return app


app = create_app()

if __name__ == '__main__':
    logger.info(f"Starting PhishGuard AI server on port {config.PORT} (debug={config.DEBUG})...")
    app.run(host='0.0.0.0', port=config.PORT, debug=config.DEBUG)
