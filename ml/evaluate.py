"""
evaluate.py - Standalone Model Evaluation and Diagnostics Script

WHAT: Inspects persisted model artifacts and displays comprehensive evaluation metrics.
WHY: Academic PBL projects require clear verification of confusion matrices,
     precision, recall, F1, and feature importance.
HOW: Reads models/evaluation_results.json and models/text_evaluation_results.json,
     formatting findings into a structured terminal report.
INPUT: Persisted evaluation JSON files.
OUTPUT: Formatted console report.
"""
import sys
import json
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))

URL_METRICS_FILE = _ROOT / 'models' / 'model_metrics.json'
URL_EVAL_FILE = _ROOT / 'models' / 'evaluation_results.json'
TEXT_EVAL_FILE = _ROOT / 'models' / 'text_evaluation_results.json'


def display_reports():
    print("\n" + "=" * 65)
    print("       PHISHGUARD AI - MODEL PERFORMANCE & EVALUATION REPORT")
    print("=" * 65)

    # 1. URL Model
    print("\n[1] URL CLASSIFIERS EVALUATION & COMPARISON")
    print("-" * 65)
    metrics_file = URL_METRICS_FILE if URL_METRICS_FILE.exists() else URL_EVAL_FILE

    if metrics_file.exists():
        with open(metrics_file, 'r', encoding='utf-8') as f:
            data = json.load(f)

        dataset_info = data.get("dataset", {})
        ds_name = dataset_info.get("name") if isinstance(dataset_info, dict) else data.get("dataset_name", "N/A")
        total_s = dataset_info.get("total_cleaned_samples") if isinstance(dataset_info, dict) else data.get("total_samples")
        train_s = dataset_info.get("train_samples") if isinstance(dataset_info, dict) else data.get("train_samples")
        test_s = dataset_info.get("test_samples") if isinstance(dataset_info, dict) else data.get("test_samples")

        print(f"  Dataset:          {ds_name}")
        print(f"  Total Samples:    {total_s:,}" if isinstance(total_s, int) else f"  Total Samples:    {total_s}")
        print(f"  Train / Test:     {train_s:,} / {test_s:,}" if isinstance(train_s, int) else f"  Train / Test:     {train_s} / {test_s}")

        # Multi-model comparison table if available
        comparison = data.get("comparison", [])
        if comparison:
            print("\n  Candidate Model Comparison (Holdout Test Split):")
            print(f"    {'Model':<22} | {'Accuracy':<10} | {'Precision':<10} | {'Recall':<10} | {'F1 Score':<10}")
            print("    " + "-" * 60)
            for c in comparison:
                print(f"    {c['model']:<22} | {c['accuracy']*100:>8.2f}% | {c['precision']*100:>8.2f}% | {c['recall']*100:>8.2f}% | {c['f1_score']*100:>8.2f}%")

        # Primary Model Metrics
        primary = data.get("primary_evaluation", data)
        p_name = data.get("primary_model", "Random Forest")
        print(f"\n  Primary Selected Architecture: {p_name}")
        print(f"    Holdout Accuracy:  {primary.get('accuracy', 0) * 100:.2f}%")
        print(f"    Precision (Phish): {primary.get('precision', 0) * 100:.2f}%")
        print(f"    Recall (Phish):    {primary.get('recall', 0) * 100:.2f}%")
        print(f"    F1 Score:          {primary.get('f1_score', 0) * 100:.2f}%")

        cm = primary.get('confusion_matrix', {})
        print(f"\n    Holdout Confusion Matrix:")
        print(f"      True Negative  (Legitimate as Legitimate): {cm.get('true_negative'):,}")
        print(f"      False Positive (Legitimate as Phishing):   {cm.get('false_positive'):,}")
        print(f"      False Negative (Phishing as Legitimate):   {cm.get('false_negative'):,}")
        print(f"      True Positive  (Phishing as Phishing):     {cm.get('true_positive'):,}")

        print(f"\n    Top 5 Most Informative Features (Gini Importance):")
        for item in data.get('feature_importance', [])[:5]:
            print(f"      - {item['feature']:<25} : {item['importance']:.4f}")
    else:
        print("  Model has not been trained yet. Run: python ml/train_url_model.py")

    # 2. Text / Message Model
    print("\n[2] MESSAGE / EMAIL CLASSIFIER (TF-IDF + Logistic Regression)")
    print("-" * 65)
    if TEXT_EVAL_FILE.exists():
        with open(TEXT_EVAL_FILE, 'r', encoding='utf-8') as f:
            tdata = json.load(f)
        print(f"  Dataset:          {tdata.get('dataset_name', 'N/A')}")
        print(f"  Total Samples:    {tdata.get('total_samples')}")
        print(f"  Accuracy:         {tdata.get('accuracy') * 100:.2f}%")
        print(f"  Precision:        {tdata.get('precision') * 100:.2f}%")
        print(f"  Recall:           {tdata.get('recall') * 100:.2f}%")
        print(f"  F1 Score:         {tdata.get('f1_score') * 100:.2f}%")

        cm = tdata.get('confusion_matrix', {})
        print(f"\n  Confusion Matrix:")
        print(f"    True Negative  (Legitimate as Legitimate): {cm.get('true_negative')}")
        print(f"    False Positive (Legitimate as Phishing):   {cm.get('false_positive')}")
        print(f"    False Negative (Phishing as Legitimate):   {cm.get('false_negative')}")
        print(f"    True Positive  (Phishing as Phishing):     {cm.get('true_positive')}")

        print(f"\n  Top Predictive Phishing Phrasing:")
        for item in tdata.get('top_phishing_features', [])[:5]:
            print(f"    - '{item['term']}': weight +{item['weight']}")
    else:
        print("  Text model has not been trained yet. Run: python ml/train_text_model.py")

    print("\n" + "=" * 65 + "\n")


if __name__ == '__main__':
    display_reports()
