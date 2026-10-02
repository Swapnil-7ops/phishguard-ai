# PhishGuard AI - Dataset Documentation

## Overview
This directory stores datasets utilized for training and evaluating the URL and text classification machine learning models.

## 1. URL Phishing Dataset: PhiUSIIL (UCI Machine Learning Repository)
- **Primary file path**: `data/datasets/phishing_urls.csv`
- **Raw source file**: `data/datasets/PhiUSIIL_Phishing_URL_Dataset.csv`
- **Source**: UCI Machine Learning Repository (Dataset ID: 967)
- **Link**: https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset
- **Reference**: Prasad, A., & Chandra, S. (2024). *PhiUSIIL: A diverse and comprehensive dataset for phishing URL detection*. Computers & Security, 103545.

### Dataset Profile:
- **Raw Sample Count**: 235,795 URLs
- **Raw Columns**: 56 columns (including `FILENAME`, `URL`, `label`, and diverse page-level metrics)
- **URL Column**: `URL`
- **Raw Label Column**: `label`
- **Raw Label Encoding**:
  - `1` = Legitimate (134,850 samples)
  - `0` = Phishing (100,945 samples)

### Preprocessing & Normalized Schema (`data/datasets/phishing_urls.csv`):
- **Duplicates Removed**: 425 duplicate URLs
- **Total Cleaned Samples**: 235,370 URLs
- **Normalized Schema**:
  - `url` (string): The uniform resource locator string.
  - `label` (integer):
    - `0` = Legitimate (134,850 samples, 57.29%)
    - `1` = Phishing (100,520 samples, 42.71%)
- **Data Hygiene**: Stripped whitespace, dropped duplicates, validated string type, no external HTTP network requests (static lexical evaluation).

## 2. Text / Message Phishing Dataset
- **Primary file path**: `data/datasets/phishing_messages.csv`
- **Schema requirements**:
  - `text` (string): The message body (SMS, email subject/body, notification).
  - `label` (integer): `0` = Legitimate / Ham, `1` = Phishing / Scam / Smishing.
- **Benchmark Source**: SMS Spam Collection Dataset (UCI Machine Learning Repository)

## 3. Dataset Preprocessing & Model Training
To execute the reproducible dataset preprocessing, 25-feature extraction, model training, comparison, and evaluation pipeline:
```bash
python ml/train_url_model.py
```
This trains Logistic Regression, Decision Tree, and Random Forest, compares metrics, generates confusion matrices, and persists artifacts to `models/`.
