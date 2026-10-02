"""
config.py - Application Configuration Module

WHAT: Centralizes all configuration loaded from environment variables.
WHY: Avoids hardcoded secrets, allows easy environment switching, and provides typed paths.
HOW: Uses python-dotenv to load the .env file, then reads variables via os.getenv.
INPUT: Environment variables (.env or OS environment).
OUTPUT: Config object exposing directories, database settings, keys, and model paths.
LIMITATIONS: Values are loaded on module import; runtime changes to .env require app restart.
"""
import os
from pathlib import Path
from dotenv import load_dotenv

# Load .env file from project root
_base_dir = Path(__file__).resolve().parent
load_dotenv(_base_dir / '.env')


class Config:
    """Central application configuration."""

    # Base paths
    BASE_DIR: Path = _base_dir
    MODELS_DIR: Path = BASE_DIR / 'models'
    DATA_DIR: Path = BASE_DIR / 'data' / 'datasets'
    UPLOAD_DIR: Path = BASE_DIR / 'uploads'
    DOCS_DIR: Path = BASE_DIR / 'docs'

    # Flask Settings
    SECRET_KEY: str = os.getenv('FLASK_SECRET_KEY', 'phishguard-default-dev-secret-key')
    DEBUG: bool = os.getenv('DEBUG', 'True').lower() in ('true', '1', 't')
    PORT: int = int(os.getenv('PORT', '5000'))
    MAX_CONTENT_LENGTH: int = int(os.getenv('MAX_UPLOAD_SIZE_MB', '10')) * 1024 * 1024  # bytes

    # MongoDB Settings (support MONGODB_URI / MONGO_URI and MONGODB_DATABASE / DATABASE_NAME)
    MONGODB_URI: str = os.getenv('MONGODB_URI') or os.getenv('MONGO_URI', 'mongodb://localhost:27017/')
    MONGO_URI: str = MONGODB_URI  # alias for backward compatibility
    MONGODB_DATABASE: str = os.getenv('MONGODB_DATABASE') or os.getenv('DATABASE_NAME', 'phishguard')
    DATABASE_NAME: str = MONGODB_DATABASE  # alias for backward compatibility

    # LLM Settings (all optional)
    LLM_PROVIDER: str = os.getenv('LLM_PROVIDER', '').lower().strip()
    OPENAI_API_KEY: str = os.getenv('OPENAI_API_KEY', '').strip()
    GEMINI_API_KEY: str = os.getenv('GEMINI_API_KEY', '').strip()

    # Privacy Settings
    STORE_RAW_CONTENT: bool = os.getenv('STORE_RAW_CONTENT', 'true').lower() in ('true', '1', 't')

    # Model file paths
    URL_MODEL_PATH: Path = MODELS_DIR / 'url_model.pkl'
    TEXT_MODEL_PATH: Path = MODELS_DIR / 'text_model.pkl'
    TEXT_VECTORIZER_PATH: Path = MODELS_DIR / 'text_vectorizer.pkl'
    FEATURE_CONFIG_PATH: Path = MODELS_DIR / 'feature_config.json'
    TEXT_FEATURE_CONFIG_PATH: Path = MODELS_DIR / 'text_feature_config.json'
    MODEL_METRICS_PATH: Path = MODELS_DIR / 'model_metrics.json'
    TEXT_MODEL_METRICS_PATH: Path = MODELS_DIR / 'text_model_metrics.json'
    EVAL_RESULTS_PATH: Path = MODELS_DIR / 'evaluation_results.json'
    TEXT_EVAL_PATH: Path = MODELS_DIR / 'text_evaluation_results.json'

    # Model Version
    MODEL_VERSION: str = os.getenv('MODEL_VERSION', '1.0.0')

    # Threat Intelligence Settings (OPTIONAL - system works without any TI configured)
    VIRUSTOTAL_API_KEY: str = os.getenv('VIRUSTOTAL_API_KEY', '').strip()
    THREAT_INTEL_TIMEOUT_SEC: float = float(os.getenv('THREAT_INTEL_TIMEOUT_SEC', '5.0'))
    THREAT_INTEL_CACHE_TTL_SEC: int = int(os.getenv('THREAT_INTEL_CACHE_TTL_SEC', '3600'))  # 1 hour default

    # Allowed file extensions for QR / screenshot uploads
    ALLOWED_IMAGE_EXTENSIONS: set = {'png', 'jpg', 'jpeg', 'gif', 'bmp', 'webp'}

    @classmethod
    def ensure_dirs(cls) -> None:
        """Ensure all required runtime directories exist."""
        cls.MODELS_DIR.mkdir(parents=True, exist_ok=True)
        cls.DATA_DIR.mkdir(parents=True, exist_ok=True)
        cls.UPLOAD_DIR.mkdir(parents=True, exist_ok=True)


config = Config()
