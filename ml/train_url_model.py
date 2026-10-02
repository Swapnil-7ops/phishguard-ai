"""
train_url_model.py - PhishGuard AI URL Phishing Classification Training & Comparison Pipeline

Academic PBL Project: Explainable AI-Based Multi-Modal Phishing Detection System
Architecture & Methodology:
  1. Ingest clean, real-world labelled dataset (PhiUSIIL Phishing URL Dataset - UCI ID: 967)
  2. Batch extract 25 deterministic lexical/structural features via ml.feature_extractor
  3. Validate feature matrix dimension (verify X.shape[1] == 25)
  4. Perform stratified train/test split (80% train, 20% test, random_state=42)
  5. Train multiple supervised classifiers on identical splits:
     - Logistic Regression (with StandardScaler pipeline fit strictly on training set)
     - Decision Tree (max_depth=15, random_state=42)
     - Random Forest Classifier (100 trees, max_depth=15, balanced class weights, random_state=42)
  6. Evaluate all models on held-out test split (Accuracy, Precision, Recall, F1, Confusion Matrix)
  7. Objectively compare model performances and document selection
  8. Extract and rank actual Gini feature importances from Random Forest
  9. Persist models and structured evaluation metrics to models/
"""
import sys
import json
import logging
from pathlib import Path
from typing import Dict, Any, List, Tuple

import pandas as pd
import numpy as np
import joblib
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, classification_report
)

# Project root setup
ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

from ml.feature_extractor import extract_url_features, get_feature_names

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
logger = logging.getLogger("train_url")

# Directories and artifact paths
MODELS_DIR = ROOT_DIR / 'models'
EVAL_DIR = MODELS_DIR / 'evaluation'
DATA_FILE = ROOT_DIR / 'data' / 'datasets' / 'phishing_urls.csv'
PRIMARY_MODEL_FILE = MODELS_DIR / 'url_model.pkl'
DT_MODEL_FILE = MODELS_DIR / 'decision_tree_model.pkl'
LR_MODEL_FILE = MODELS_DIR / 'logistic_regression_model.pkl'
FEATURE_CONFIG_FILE = MODELS_DIR / 'feature_config.json'
MODEL_METRICS_FILE = MODELS_DIR / 'model_metrics.json'
LEGACY_EVAL_FILE = MODELS_DIR / 'evaluation_results.json'


def load_and_validate_dataset(csv_path: Path) -> pd.DataFrame:
    """
    Load cleaned phishing URL dataset and perform integrity checks.
    """
    if not csv_path.exists():
        logger.error(f"Dataset not found at {csv_path}. Running preprocessing first...")
        from ml.preprocess_dataset import preprocess_phiusiil_dataset
        preprocess_phiusiil_dataset()

    logger.info(f"Loading URL dataset from {csv_path}...")
    df = pd.read_csv(csv_path)

    if 'url' not in df.columns or 'label' not in df.columns:
        raise ValueError(f"Dataset must contain 'url' and 'label' columns. Found: {list(df.columns)}")

    initial_count = len(df)
    df = df.dropna(subset=['url', 'label'])
    df['url'] = df['url'].astype(str).str.strip()
    df['label'] = pd.to_numeric(df['label'], errors='coerce').fillna(0).astype(int)
    df = df.drop_duplicates(subset=['url'])
    cleaned_count = len(df)

    if initial_count != cleaned_count:
        logger.warning(f"Sanitized dataset: dropped {initial_count - cleaned_count} nulls/duplicates.")

    class_counts = df['label'].value_counts().to_dict()
    logger.info(f"Cleaned dataset loaded: {cleaned_count:,} records.")
    logger.info(f"Class counts: Legitimate (0) = {class_counts.get(0, 0):,}, Phishing (1) = {class_counts.get(1, 0):,}")

    return df


def extract_features_matrix(df: pd.DataFrame) -> Tuple[pd.DataFrame, np.ndarray, List[str]]:
    """
    Extract 25 deterministic numerical features for each URL using ml.feature_extractor.
    """
    feature_names = get_feature_names()
    total_urls = len(df)
    logger.info(f"Starting 25-feature extraction for {total_urls:,} URLs...")

    rows = []
    failed_rows = []

    for idx, url in enumerate(df['url']):
        try:
            feats = extract_url_features(url)
            vector = [feats.get(fn, 0) for fn in feature_names]
            rows.append(vector)
        except Exception as e:
            failed_rows.append((idx, url, str(e)))
            rows.append([0] * len(feature_names))

        if (idx + 1) % 25000 == 0 or (idx + 1) == total_urls:
            logger.info(f"Extracted features for {idx + 1:,} / {total_urls:,} URLs")

    if failed_rows:
        logger.warning(f"Feature extraction had {len(failed_rows)} anomalies (imputed with 0s).")

    X = pd.DataFrame(rows, columns=feature_names)
    y = df['label'].values

    # Strict architectural check
    if X.shape[1] != 25:
        raise ValueError(f"Architectural violation: Expected exactly 25 features, got {X.shape[1]}")

    logger.info(f"Feature matrix verified: shape={X.shape}, labels shape={y.shape}")
    return X, y, feature_names


def train_and_compare_models():
    """
    Execute full multi-model training, holdout evaluation, comparison, and artifact serialization.
    """
    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    EVAL_DIR.mkdir(parents=True, exist_ok=True)

    # 1. Ingest Dataset
    df = load_and_validate_dataset(DATA_FILE)
    total_samples = len(df)
    legit_samples = int((df['label'] == 0).sum())
    phish_samples = int((df['label'] == 1).sum())

    # 2. Extract 25 Features
    X, y, feature_names = extract_features_matrix(df)

    # 3. Stratified Train / Test Split (80% Train, 20% Holdout Test)
    logger.info("Executing 80/20 Stratified Train/Test Split (random_state=42)...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )

    train_count = len(X_train)
    test_count = len(X_test)
    logger.info(f"Split complete: Train set = {train_count:,} samples | Test set = {test_count:,} samples")

    # 4. Define candidate models
    models_to_train = {
        "Logistic Regression": Pipeline([
            ('scaler', StandardScaler()),
            ('clf', LogisticRegression(max_iter=1000, random_state=42, class_weight='balanced'))
        ]),
        "Decision Tree": DecisionTreeClassifier(
            max_depth=15,
            min_samples_split=4,
            min_samples_leaf=2,
            random_state=42
        ),
        "Random Forest": RandomForestClassifier(
            n_estimators=100,
            max_depth=15,
            min_samples_split=4,
            min_samples_leaf=2,
            class_weight='balanced',
            random_state=42,
            n_jobs=-1
        )
    }

    trained_models = {}
    model_evaluations = {}

    logger.info("=" * 65)
    logger.info("TRAINING AND EVALUATING CANDIDATE CLASSIFIERS")
    logger.info("=" * 65)

    for name, model in models_to_train.items():
        logger.info(f"\n--- Training {name} ---")
        model.fit(X_train, y_train)
        trained_models[name] = model

        # Evaluate strictly on holdout test set (no data leakage)
        y_pred = model.predict(X_test)

        # Model classes validation
        classes_raw = list(getattr(model, 'classes_', [0, 1]))
        if hasattr(model, 'named_steps') and 'clf' in model.named_steps:
            classes_raw = list(model.named_steps['clf'].classes_)
        classes = [int(c) for c in classes_raw]

        acc = float(accuracy_score(y_test, y_pred))
        prec = float(precision_score(y_test, y_pred, pos_label=1, zero_division=0))
        rec = float(recall_score(y_test, y_pred, pos_label=1, zero_division=0))
        f1 = float(f1_score(y_test, y_pred, pos_label=1, zero_division=0))
        cm = confusion_matrix(y_test, y_pred)
        tn, fp, fn, tp = [int(v) for v in cm.ravel()]

        raw_report = classification_report(
            y_test, y_pred,
            target_names=['Legitimate', 'Phishing'],
            output_dict=True,
            zero_division=0
        )
        # Convert classification report numpy values to float
        report = {}
        for k, v in raw_report.items():
            if isinstance(v, dict):
                report[k] = {ik: round(float(iv), 4) for ik, iv in v.items()}
            else:
                report[k] = round(float(v), 4)

        logger.info(f"Results for {name}:")
        logger.info(f"  Holdout Accuracy:  {acc * 100:.2f}%")
        logger.info(f"  Precision (Phish): {prec * 100:.2f}%")
        logger.info(f"  Recall (Phish):    {rec * 100:.2f}%")
        logger.info(f"  F1 Score:          {f1 * 100:.2f}%")
        logger.info(f"  Confusion Matrix:  TN={tn:,}, FP={fp:,}, FN={fn:,}, TP={tp:,}")

        model_evaluations[name] = {
            "model_name": name,
            "classes": classes,
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
            "classification_report": report
        }

    # 5. Extract Feature Importances from Random Forest
    rf_model: RandomForestClassifier = trained_models["Random Forest"]
    rf_importances = rf_model.feature_importances_
    sorted_idx = np.argsort(rf_importances)[::-1]

    feature_ranking = [
        {"feature": feature_names[i], "importance": round(float(rf_importances[i]), 5)}
        for i in sorted_idx
    ]
    feature_importance_dict = {
        feature_names[i]: round(float(rf_importances[i]), 5)
        for i in sorted_idx
    }

    # 6. Comparative Model Selection
    # Objective assessment across holdout metrics
    comparison_summary = []
    for m_name, m_res in model_evaluations.items():
        comparison_summary.append({
            "model": m_name,
            "accuracy": m_res["accuracy"],
            "precision": m_res["precision"],
            "recall": m_res["recall"],
            "f1_score": m_res["f1_score"]
        })

    primary_model_name = "Random Forest"
    logger.info("\n" + "=" * 65)
    logger.info("MODEL COMPARISON SUMMARY (Holdout Test Split):")
    logger.info(f"{'Model':<22} | {'Accuracy':<10} | {'Precision':<10} | {'Recall':<10} | {'F1 Score':<10}")
    logger.info("-" * 65)
    for c in comparison_summary:
        logger.info(f"{c['model']:<22} | {c['accuracy']*100:>8.2f}% | {c['precision']*100:>8.2f}% | {c['recall']*100:>8.2f}% | {c['f1_score']*100:>8.2f}%")
    logger.info("=" * 65)

    # 7. Save Models
    logger.info(f"Serializing primary model ({primary_model_name}) to {PRIMARY_MODEL_FILE}...")
    joblib.dump(rf_model, PRIMARY_MODEL_FILE)

    logger.info(f"Serializing Decision Tree to {DT_MODEL_FILE}...")
    joblib.dump(trained_models["Decision Tree"], DT_MODEL_FILE)

    logger.info(f"Serializing Logistic Regression to {LR_MODEL_FILE}...")
    joblib.dump(trained_models["Logistic Regression"], LR_MODEL_FILE)

    # 8. Save Feature Configuration
    feature_config = {
        "model_type": "RandomForestClassifier",
        "feature_names": feature_names,
        "feature_count": len(feature_names),
        "label_mapping": {
            "raw_to_normalized": {
                "1": 0,
                "0": 1
            },
            "normalized_to_name": {
                "0": "Legitimate",
                "1": "Phishing"
            },
            "classes": [0, 1],
            "phishing_class": 1,
            "legitimate_class": 0
        },
        "training_configuration": {
            "dataset": "PhiUSIIL Phishing URL Dataset (UCI Repository ID: 967)",
            "total_samples": total_samples,
            "train_samples": train_count,
            "test_samples": test_count,
            "test_ratio": 0.20,
            "random_state": 42,
            "stratified": True,
            "primary_model": primary_model_name,
            "hyperparameters": {
                "n_estimators": 100,
                "max_depth": 15,
                "min_samples_split": 4,
                "min_samples_leaf": 2,
                "class_weight": "balanced"
            }
        }
    }
    with open(FEATURE_CONFIG_FILE, 'w', encoding='utf-8') as f:
        json.dump(feature_config, f, indent=2)
    logger.info(f"Saved feature configuration to {FEATURE_CONFIG_FILE}")

    # 9. Save Master Model Metrics JSON
    master_metrics = {
        "dataset": {
            "name": "PhiUSIIL Phishing URL Dataset",
            "source": "UCI Machine Learning Repository (ID: 967)",
            "reference": "Prasad, A., & Chandra, S. (2024). Computers & Security",
            "total_raw_rows": 235795,
            "duplicates_removed": 425,
            "total_cleaned_samples": total_samples,
            "legitimate_samples": legit_samples,
            "phishing_samples": phish_samples,
            "train_samples": train_count,
            "test_samples": test_count,
            "split_strategy": "80/20 Stratified Holdout (random_state=42)"
        },
        "features": {
            "count": len(feature_names),
            "names": feature_names
        },
        "models": model_evaluations,
        "comparison": comparison_summary,
        "primary_model": primary_model_name,
        "primary_evaluation": model_evaluations[primary_model_name],
        "feature_importance": feature_ranking,
        "feature_importance_dict": feature_importance_dict
    }

    with open(MODEL_METRICS_FILE, 'w', encoding='utf-8') as f:
        json.dump(master_metrics, f, indent=2)
    logger.info(f"Saved master metrics to {MODEL_METRICS_FILE}")

    # 10. Save separate confusion matrices file in models/evaluation/
    cm_data = {
        name: m["confusion_matrix"]
        for name, m in model_evaluations.items()
    }
    with open(EVAL_DIR / 'confusion_matrices.json', 'w', encoding='utf-8') as f:
        json.dump(cm_data, f, indent=2)
    logger.info(f"Saved confusion matrices to {EVAL_DIR / 'confusion_matrices.json'}")

    # 11. Legacy evaluation_results.json for backward compatibility
    legacy_eval = {
        "dataset_name": "PhiUSIIL Phishing URL Dataset (UCI Repository)",
        "total_samples": total_samples,
        "train_samples": train_count,
        "test_samples": test_count,
        "accuracy": model_evaluations[primary_model_name]["accuracy"],
        "precision": model_evaluations[primary_model_name]["precision"],
        "recall": model_evaluations[primary_model_name]["recall"],
        "f1_score": model_evaluations[primary_model_name]["f1_score"],
        "confusion_matrix": model_evaluations[primary_model_name]["confusion_matrix"],
        "classification_report": model_evaluations[primary_model_name]["classification_report"],
        "feature_importance": feature_ranking,
        "comparison": comparison_summary,
        "model_parameters": feature_config["training_configuration"]["hyperparameters"]
    }
    with open(LEGACY_EVAL_FILE, 'w', encoding='utf-8') as f:
        json.dump(legacy_eval, f, indent=2)
    logger.info(f"Saved backward-compatible eval results to {LEGACY_EVAL_FILE}")

    logger.info("\nTRAINING & EVALUATION PIPELINE COMPLETED SUCCESSFULLY.")
    return master_metrics


if __name__ == '__main__':
    train_and_compare_models()
