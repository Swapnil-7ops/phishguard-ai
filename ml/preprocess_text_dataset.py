"""
preprocess_text_dataset.py - Preprocessing Pipeline for Message / SMS Corpus

WHAT: Ingests the raw UCI SMS Spam Collection dataset, standardizes labels,
     removes duplicates, and exports clean training artifacts.
WHY: Academic rigor requires reproducible, non-hardcoded dataset accounting,
     explicit label semantics (ham -> Legitimate, spam -> Malicious/Spam),
     and verified split isolation to prevent data leakage.
HOW:
  1. Ingests raw TSV (sms_spam_collection.tsv) or downloads if absent.
  2. Dynamically counts raw rows and parses fields ('raw_label' and 'text').
  3. Maps 'ham' -> 0 (Legitimate/Ham) and 'spam' -> 1 (Malicious/Spam).
  4. Identifies and removes duplicate texts, calculating exact deduplication delta.
  5. Exports data/datasets/phishing_messages.csv and summary statistics to
     data/datasets/text_preprocessing_summary.json.

DATASET SEMANTICS NOTICE:
  The dataset is the UCI SMS Spam Collection (Almeida & Hidalgo, 2011).
  Official classes are 'ham' (benign) and 'spam' (unsolicited / scam / malicious).
  The resulting model is designated as an "SMS Spam/Malicious Message Classifier"
  serving as one evidence source in PhishGuard AI's explainable defense cascade.
"""
import sys
import json
import logging
import urllib.request
from pathlib import Path

import pandas as pd

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
logger = logging.getLogger(__name__)

DATA_DIR = _ROOT / 'data' / 'datasets'
RAW_TSV_PATH = DATA_DIR / 'sms_spam_collection.tsv'
OUTPUT_CSV_PATH = DATA_DIR / 'phishing_messages.csv'
SUMMARY_JSON_PATH = DATA_DIR / 'text_preprocessing_summary.json'

UCI_SMS_URL = "https://raw.githubusercontent.com/justmarkham/DAT8/master/data/sms.tsv"


def download_raw_dataset_if_needed() -> Path:
    """Download the raw UCI SMS spam dataset if not already present on disk."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    if not RAW_TSV_PATH.exists():
        logger.info(f"Downloading raw dataset from {UCI_SMS_URL} to {RAW_TSV_PATH}...")
        urllib.request.urlretrieve(UCI_SMS_URL, RAW_TSV_PATH)
        logger.info(f"Download complete: {RAW_TSV_PATH.stat().st_size} bytes.")
    else:
        logger.info(f"Raw dataset already exists at {RAW_TSV_PATH} ({RAW_TSV_PATH.stat().st_size} bytes).")
    return RAW_TSV_PATH


def preprocess_messages() -> dict:
    """
    Execute end-to-end preprocessing with dynamic row counting and label normalization.
    """
    tsv_path = download_raw_dataset_if_needed()

    logger.info("Reading raw TSV dataset...")
    # Read using sep='\t', quotechar=None (quoting=3) to prevent quote-splitting
    df_raw = pd.read_csv(
        tsv_path,
        sep='\t',
        header=None,
        names=['raw_label', 'text'],
        dtype=str,
        on_bad_lines='skip',
        quoting=3,
        encoding='utf-8'
    )

    raw_row_count = int(len(df_raw))
    logger.info(f"Raw rows ingested dynamically: {raw_row_count}")

    # Drop missing or completely blank rows
    df_clean = df_raw.dropna(subset=['raw_label', 'text']).copy()
    df_clean['raw_label'] = df_clean['raw_label'].astype(str).str.strip().str.lower()
    df_clean['text'] = df_clean['text'].astype(str).str.strip()
    df_clean = df_clean[df_clean['text'] != '']
    df_clean = df_clean[df_clean['raw_label'].isin(['ham', 'spam'])]

    parsed_row_count = int(len(df_clean))

    # Map labels: ham -> 0 (Legitimate/Ham), spam -> 1 (Malicious/Spam)
    label_mapping = {'ham': 0, 'spam': 1}
    df_clean['label'] = df_clean['raw_label'].map(label_mapping)

    # Calculate duplicates dynamically
    duplicates_count = int(df_clean.duplicated(subset=['text']).sum())
    df_dedup = df_clean.drop_duplicates(subset=['text'], keep='first').copy()
    final_row_count = int(len(df_dedup))

    ham_count = int((df_dedup['label'] == 0).sum())
    spam_count = int((df_dedup['label'] == 1).sum())

    logger.info(f"Parsed rows: {parsed_row_count}")
    logger.info(f"Duplicate messages dropped dynamically: {duplicates_count}")
    logger.info(f"Final unique dataset rows: {final_row_count}")
    logger.info(f"  - Legitimate / Ham (0): {ham_count} ({ham_count/final_row_count*100:.2f}%)")
    logger.info(f"  - Malicious / Spam  (1): {spam_count} ({spam_count/final_row_count*100:.2f}%)")

    # Export clean training CSV
    export_df = df_dedup[['text', 'label']].copy()
    export_df.to_csv(OUTPUT_CSV_PATH, index=False, encoding='utf-8')
    logger.info(f"Cleaned messages saved to {OUTPUT_CSV_PATH}")

    summary = {
        "dataset_name": "UCI SMS Spam Collection",
        "official_source": "UCI Machine Learning Repository / Tiago A. Almeida & José María Gómez Hidalgo",
        "model_role": "SMS Spam/Malicious Message Classifier",
        "label_semantics": {
            "0": "Legitimate/Ham",
            "1": "Malicious/Spam"
        },
        "statistics": {
            "raw_rows_ingested": raw_row_count,
            "valid_parsed_rows": parsed_row_count,
            "dropped_duplicates": duplicates_count,
            "final_cleaned_rows": final_row_count,
            "ham_count": ham_count,
            "spam_count": spam_count,
            "spam_ratio": round(spam_count / final_row_count, 4)
        }
    }

    with open(SUMMARY_JSON_PATH, 'w', encoding='utf-8') as f:
        json.dump(summary, f, indent=2)
    logger.info(f"Preprocessing summary saved to {SUMMARY_JSON_PATH}")

    return summary


if __name__ == '__main__':
    preprocess_messages()

