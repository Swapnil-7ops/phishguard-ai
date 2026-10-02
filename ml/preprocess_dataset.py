"""
preprocess_dataset.py - Dataset Preprocessing Pipeline for PhishGuard AI

WHAT: Preprocesses the official UCI PhiUSIIL Phishing URL Dataset.
WHY: Ensures clean, validated, reproducible data without duplicates or missing values,
     with explicit label mapping (0 = Legitimate, 1 = Phishing).
HOW:
  1. Locates PhiUSIIL_Phishing_URL_Dataset.csv (or downloads it from UCI).
  2. Inspects and strips URL strings.
  3. Drops duplicate URLs.
  4. Normalizes labels:
       Raw 1 (Legitimate in PhiUSIIL) -> Normalized 0 (Legitimate)
       Raw 0 (Phishing in PhiUSIIL)   -> Normalized 1 (Phishing)
  5. Exports cleaned data/datasets/phishing_urls.csv.
  6. Generates preprocessing audit report.
"""
import os
import sys
import json
import logging
from pathlib import Path
import pandas as pd

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
logger = logging.getLogger("preprocess")

ROOT_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT_DIR / 'data' / 'datasets'
RAW_DATASET_FILE = DATA_DIR / 'PhiUSIIL_Phishing_URL_Dataset.csv'
CLEAN_DATASET_FILE = DATA_DIR / 'phishing_urls.csv'
REPORT_FILE = DATA_DIR / 'preprocessing_summary.json'


def preprocess_phiusiil_dataset():
    if not RAW_DATASET_FILE.exists():
        logger.info(f"Raw dataset file not found at {RAW_DATASET_FILE}. Attempting UCI download...")
        import urllib.request
        import zipfile
        import io
        url = "https://archive.ics.uci.edu/static/public/967/phiusiil+phishing+url+dataset.zip"
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=90) as resp:
            data = resp.read()
            with zipfile.ZipFile(io.BytesIO(data)) as z:
                z.extractall(DATA_DIR)
        logger.info(f"Downloaded and extracted raw dataset to {DATA_DIR}")

    logger.info(f"Reading raw dataset from {RAW_DATASET_FILE}...")
    df = pd.read_csv(RAW_DATASET_FILE, usecols=['URL', 'label'])
    original_row_count = len(df)

    # Missing value handling
    df = df.dropna(subset=['URL', 'label'])
    after_na = len(df)
    missing_removed = original_row_count - after_na

    # URL string cleanup
    df['URL'] = df['URL'].astype(str).str.strip()
    df = df[df['URL'] != '']

    # Duplicate removal
    df = df.drop_duplicates(subset=['URL'])
    final_row_count = len(df)
    duplicates_removed = after_na - final_row_count

    # Label normalization:
    # In official PhiUSIIL (UCI ID 967):
    #   1 = Legitimate (134,850 samples)
    #   0 = Phishing   (100,945 samples)
    #
    # PhishGuard AI standard binary representation:
    #   0 = Legitimate (majority/negative class)
    #   1 = Phishing   (threat/positive class)
    raw_counts = df['label'].value_counts().to_dict()
    df['normalized_label'] = (df['label'] == 0).astype(int)

    legit_count = int((df['normalized_label'] == 0).sum())
    phish_count = int((df['normalized_label'] == 1).sum())

    # Format output dataframe with standard columns: url, label
    cleaned_df = pd.DataFrame({
        'url': df['URL'],
        'label': df['normalized_label']
    })

    logger.info(f"Writing cleaned dataset to {CLEAN_DATASET_FILE}...")
    cleaned_df.to_csv(CLEAN_DATASET_FILE, index=False, encoding='utf-8')

    summary = {
        "dataset_name": "PhiUSIIL Phishing URL Dataset",
        "source": "UCI Machine Learning Repository (ID: 967)",
        "reference": "Prasad, A., & Chandra, S. (2024). Computers & Security",
        "original_row_count": original_row_count,
        "missing_removed": missing_removed,
        "duplicates_removed": duplicates_removed,
        "final_row_count": final_row_count,
        "raw_label_distribution": {
            "1_legitimate": raw_counts.get(1, 0),
            "0_phishing": raw_counts.get(0, 0)
        },
        "normalized_label_distribution": {
            "0_legitimate": legit_count,
            "1_phishing": phish_count
        },
        "class_proportions": {
            "legitimate_pct": round((legit_count / final_row_count) * 100, 2),
            "phishing_pct": round((phish_count / final_row_count) * 100, 2)
        },
        "label_mapping": {
            "raw_to_normalized": {
                "1": 0,
                "0": 1
            },
            "normalized_to_name": {
                "0": "Legitimate",
                "1": "Phishing"
            },
            "phishing_class": 1,
            "legitimate_class": 0
        }
    }

    with open(REPORT_FILE, 'w', encoding='utf-8') as f:
        json.dump(summary, f, indent=2)

    logger.info("=" * 60)
    logger.info("DATASET PREPROCESSING COMPLETE")
    logger.info(f"Original Row Count:        {original_row_count:,}")
    logger.info(f"Duplicates Removed:        {duplicates_removed:,}")
    logger.info(f"Final Cleaned Samples:     {final_row_count:,}")
    logger.info(f"  - Legitimate (Class 0):  {legit_count:,} ({summary['class_proportions']['legitimate_pct']}%)")
    logger.info(f"  - Phishing   (Class 1):  {phish_count:,} ({summary['class_proportions']['phishing_pct']}%)")
    logger.info(f"Cleaned CSV:               {CLEAN_DATASET_FILE}")
    logger.info(f"Summary JSON:              {REPORT_FILE}")
    logger.info("=" * 60)

    return summary


if __name__ == '__main__':
    preprocess_phiusiil_dataset()
