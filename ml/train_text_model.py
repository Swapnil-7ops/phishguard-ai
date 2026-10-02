"""
train_text_model.py - Phishing / Malicious Message Classification Training Pipeline

WHAT: Trains a TF-IDF + LogisticRegression NLP model on the UCI SMS Spam Collection.
WHY: Social engineering and smishing attacks abuse psychological manipulation (urgency,
     account locking, OTP solicitation). TF-IDF captures informative unigrams and bigrams,
     while Logistic Regression provides interpretable log-odds weights without data leakage.
HOW:
  1. Loads preprocessed messages (data/datasets/phishing_messages.csv).
  2. Partitions into stratified 80/20 train and test sets (random_state=42).
  3. Fits TfidfVectorizer STRICTLY on X_train to prevent data leakage; transforms X_test.
  4. Trains LogisticRegression with class_weight='balanced'.
  5. Dynamically inspects model.classes_ to ensure class index safety.
  6. Evaluates holdout accuracy, precision, recall, F1, and confusion matrix.
  7. Persists:
       - models/text_model.pkl
       - models/text_vectorizer.pkl
       - models/text_model_metrics.json
       - models/text_feature_config.json
       - models/text_evaluation_results.json (backward-compatible copy)

DATASET & MODEL SEMANTICS:
  Trained on the UCI SMS Spam Collection (Almeida & Hidalgo, 2011).
  Official classes: 0 -> Legitimate/Ham, 1 -> Malicious/Spam.
  Described as: "SMS Spam/Malicious Message Classifier"
"""
import sys
import json
import logging
from pathlib import Path

import pandas as pd
import numpy as np
import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, classification_report
)

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
logger = logging.getLogger(__name__)

MODELS_DIR = _ROOT / 'models'
DATA_FILE = _ROOT / 'data' / 'datasets' / 'phishing_messages.csv'
SUMMARY_FILE = _ROOT / 'data' / 'datasets' / 'text_preprocessing_summary.json'

MODEL_FILE = MODELS_DIR / 'text_model.pkl'
VEC_FILE = MODELS_DIR / 'text_vectorizer.pkl'
METRICS_FILE = MODELS_DIR / 'text_model_metrics.json'
FEATURE_CONFIG_FILE = MODELS_DIR / 'text_feature_config.json'
LEGACY_EVAL_FILE = MODELS_DIR / 'text_evaluation_results.json'


def load_dataset() -> pd.DataFrame:
    """Load cleaned message dataset from disk."""
    if not DATA_FILE.exists():
        logger.info(f"Dataset {DATA_FILE} not found. Running preprocessor...")
        from ml.preprocess_text_dataset import preprocess_messages
        preprocess_messages()

    df = pd.read_csv(DATA_FILE)
    df = df.dropna(subset=['text', 'label'])
    df['text'] = df['text'].astype(str).str.strip()
    df['label'] = pd.to_numeric(df['label'], errors='coerce').astype(int)
    df = df[df['text'] != '']
    return df


def train_text_classifier():
    """Execute model training, validation, and serialization."""
    MODELS_DIR.mkdir(parents=True, exist_ok=True)

    df = load_dataset()
    total_samples = len(df)
    ham_total = int((df['label'] == 0).sum())
    spam_total = int((df['label'] == 1).sum())

    logger.info(f"Loaded {total_samples} samples (Legitimate/Ham={ham_total}, Malicious/Spam={spam_total}).")

    X = df['text'].values
    y = df['label'].values

    # Stratified 80/20 train/test split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )

    train_samples = len(X_train)
    test_samples = len(X_test)
    logger.info(f"Dataset split: {train_samples} train / {test_samples} test (stratified).")

    # Vectorizer fitted STRICTLY on X_train to prevent data leakage
    vectorizer = TfidfVectorizer(
        max_features=3000,
        ngram_range=(1, 2),
        lowercase=True,
        stop_words='english',
        strip_accents='unicode',
        sublinear_tf=True
    )

    logger.info("Fitting TF-IDF Vectorizer on training partition only...")
    X_train_vec = vectorizer.fit_transform(X_train)
    logger.info(f"TF-IDF vocabulary built: {len(vectorizer.vocabulary_)} features.")

    # Transform test set without re-fitting
    X_test_vec = vectorizer.transform(X_test)

    # Train Logistic Regression
    clf = LogisticRegression(
        C=1.5,
        max_iter=1000,
        class_weight='balanced',
        random_state=42,
        solver='lbfgs'
    )
    logger.info("Fitting Logistic Regression with balanced class weights...")
    clf.fit(X_train_vec, y_train)

    # Dynamic class index verification
    classes = list(clf.classes_)
    if 1 not in classes:
        raise ValueError(f"Malicious class 1 missing from model classes: {classes}")
    malicious_idx = classes.index(1)
    legitimate_idx = classes.index(0)
    logger.info(f"Verified model classes: {classes} (Malicious index={malicious_idx}, Legitimate index={legitimate_idx})")

    # Evaluate holdout performance
    y_pred = clf.predict(X_test_vec)
    y_prob = clf.predict_proba(X_test_vec)[:, malicious_idx]

    acc = float(accuracy_score(y_test, y_pred))
    prec = float(precision_score(y_test, y_pred, pos_label=1, zero_division=0))
    rec = float(recall_score(y_test, y_pred, pos_label=1, zero_division=0))
    f1 = float(f1_score(y_test, y_pred, pos_label=1, zero_division=0))

    cm = confusion_matrix(y_test, y_pred, labels=[0, 1])
    tn, fp, fn, tp = [int(v) for v in cm.ravel()]

    report = classification_report(
        y_test, y_pred,
        labels=[0, 1],
        target_names=['Legitimate/Ham', 'Malicious/Spam'],
        output_dict=True
    )

    logger.info("Holdout Evaluation Metrics:")
    logger.info(f"  Accuracy:  {acc * 100:.2f}%")
    logger.info(f"  Precision: {prec * 100:.2f}%")
    logger.info(f"  Recall:    {rec * 100:.2f}%")
    logger.info(f"  F1-Score:  {f1 * 100:.2f}%")
    logger.info(f"  Confusion Matrix: TN={tn}, FP={fp}, FN={fn}, TP={tp}")

    # Top indicative vocabulary coefficients
    feature_names = vectorizer.get_feature_names_out()
    coefs = clf.coef_[0]
    top_spam_indices = np.argsort(coefs)[::-1][:20]
    top_ham_indices = np.argsort(coefs)[:20]

    top_indicative_spam = [
        {"term": str(feature_names[i]), "weight": round(float(coefs[i]), 4)}
        for i in top_spam_indices
    ]
    top_indicative_ham = [
        {"term": str(feature_names[i]), "weight": round(float(coefs[i]), 4)}
        for i in top_ham_indices
    ]

    # Save trained model and vectorizer
    logger.info(f"Persisting model artifact -> {MODEL_FILE}")
    joblib.dump(clf, MODEL_FILE)
    logger.info(f"Persisting vectorizer artifact -> {VEC_FILE}")
    joblib.dump(vectorizer, VEC_FILE)

    # Feature and vocabulary metadata configuration
    feature_config = {
        "model_architecture": "TF-IDF + LogisticRegression",
        "classifier_name": "SMS Spam/Malicious Message Classifier",
        "vectorizer_type": "TfidfVectorizer",
        "max_features": 3000,
        "ngram_range": [1, 2],
        "sublinear_tf": True,
        "stop_words": "english",
        "strip_accents": "unicode",
        "vocabulary_size": len(vectorizer.vocabulary_),
        "classes": [int(c) for c in classes],
        "label_mapping": {
            "0": "Legitimate/Ham",
            "1": "Malicious/Spam"
        },
        "target_class": 1,
        "target_class_name": "Malicious/Spam",
        "class_index_in_predict_proba": malicious_idx
    }

    with open(FEATURE_CONFIG_FILE, 'w', encoding='utf-8') as f:
        json.dump(feature_config, f, indent=2)
    logger.info(f"Persisted feature config -> {FEATURE_CONFIG_FILE}")

    # Metrics JSON
    metrics_payload = {
        "model_name": "TF-IDF + Logistic Regression",
        "classifier_description": "SMS Spam/Malicious Message Classifier",
        "dataset": {
            "name": "UCI SMS Spam Collection",
            "source": "UCI Machine Learning Repository",
            "total_cleaned_samples": total_samples,
            "train_samples": train_samples,
            "test_samples": test_samples,
            "ham_samples": ham_total,
            "spam_samples": spam_total
        },
        "accuracy": round(acc, 4),
        "precision": round(prec, 4),
        "recall": round(rec, 4),
        "f1_score": round(f1, 4),
        "confusion_matrix": {
            "true_negative": tn,
            "false_positive": fp,
            "false_negative": fn,
            "true_positive": tp
        },
        "classification_report": report,
        "top_indicative_terms": {
            "spam_malicious": top_indicative_spam,
            "legitimate_ham": top_indicative_ham
        },
        "split_method": "Stratified 80/20 train/test split, random_state=42"
    }

    with open(METRICS_FILE, 'w', encoding='utf-8') as f:
        json.dump(metrics_payload, f, indent=2)
    logger.info(f"Persisted model metrics -> {METRICS_FILE}")

    # Also write legacy evaluation results file for backward compatibility
    with open(LEGACY_EVAL_FILE, 'w', encoding='utf-8') as f:
        json.dump(metrics_payload, f, indent=2)

    return metrics_payload


if __name__ == '__main__':
    train_text_classifier()
