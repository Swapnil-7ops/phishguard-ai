# PhishGuard AI - Machine Learning Methodology

## 1. Problem Formulation
Phishing detection is framed as a supervised binary classification problem:
$$y \in \{0, 1\}$$
where $y = 0$ represents a Legitimate (benign) resource, and $y = 1$ represents a Phishing (malicious) resource.

The system deploys two distinct ML models:
1. **URL Classifier:** Supervised non-linear classification on 25 engineered continuous and discrete features.
2. **Message Classifier:** Supervised linear classification on sparse high-dimensional TF-IDF lexical n-grams (training pending).

---

## 2. URL Classification Pipeline (Phase 4 — Live Integration)

### 2.1 Complete URL Analysis Pipeline

```
User Input (URL string)
        ↓
[1] Input Validation & Normalization
    - Reject dangerous schemes (javascript:, data:, file:, vbscript:)
    - Reject URLs > 2048 characters
    - Normalize scheme to lowercase (http/https)
    - Canonicalize hostname to lowercase
        ↓
[2] Static Feature Extraction (ml/feature_extractor.py)
    - 25 deterministic features extracted via regex, urlparse, tldextract
    - NO HTTP requests made — pure string/lexical analysis
    - Returns Dict[str, Union[int, float]] with 25 keys
        ↓
[3] Feature Vector Assembly
    - Features ordered exactly as per feature_config.json
    - pandas DataFrame constructed with column names matching training
    - NaN/None values replaced with 0 (safe fallback)
        ↓
[4] Random Forest Inference (models/url_model.pkl)
    - model.predict_proba(X_df) → probability vector
    - Phishing class identified via model.classes_ (NEVER assumed to be index 1)
    - phishing_prob = probs[classes.index(phishing_class_label)]
        ↓
[5] Rule Engine Evaluation (services/rule_engine.py)
    - 13 deterministic heuristic rules evaluated against extracted features
    - Each triggered rule returns rule_id, name, severity, score_impact, description
        ↓
[6] Risk Score Synthesis (services/risk_engine.py)
    Formula:
      ML_Base      = round(phishing_prob × 60)   → max 60 points
      Rule_Impact  = min(sum(rule.score_impact), 40)  → max 40 points
      Risk_Score   = min(100, ML_Base + Rule_Impact)  → bounded [0, 100]
        ↓
[7] Explainable Output
    - prediction: Phishing | Suspicious | Legitimate
    - ml_probability_estimate: float [0.0, 1.0]  (NOT called "confidence")
    - risk_score: int [0, 100]
    - risk_level: Low | Medium | High | Critical
    - triggered_rules: list of fired rule objects
    - reasons: human-readable explanation list
    - features: full 25-feature dict
```

### 2.2 Class Label Mapping
The trained model uses:
- `classes_ = [0, 1]` where `0 = Legitimate`, `1 = Phishing`
- This is verified at load time from `feature_config.json → label_mapping`
- The phishing class index is **never hardcoded** — always resolved as:
  ```python
  phish_idx = list(model.classes_).index(label_config["phishing_class"])
  phishing_prob = model.predict_proba(X)[0][phish_idx]
  ```

### 2.3 Safe Model Loading
- Model loaded lazily and cached in `_MODEL_CACHE` (module-level singleton)
- If `models/url_model.pkl` is absent: application continues in heuristic-only mode
- No Flask crash on missing/corrupt model files
- API clearly signals `model_loaded: false` when operating without ML

### 2.4 Why Random Forest?
- **Non-Linear Interactions:** Phishing URLs exhibit complex combinatorial rules (e.g., high length is normal on e-commerce, but high length combined with an IP address and brand keywords strongly indicates malicious intent).
- **Resistance to Overfitting:** Individual decision trees suffer from high variance. Random Forest reduces variance via **Bootstrap Aggregating (Bagging)** and **Random Feature Subsampling**.
- **Interpretability via Feature Importance:** Computes Mean Decrease in Impurity (Gini Importance), identifying which structural properties contributed most to tree splits.
- **Fast Deterministic Inference:** Prediction across 100 trees executes in sub-millisecond time, suitable for low-latency web APIs.

### 2.5 Mathematical Mechanics
For an ensemble of $B$ decision trees $\{T_1, T_2, \dots, T_B\}$:
$$\hat{p}(y = 1 \mid \mathbf{x}) = \frac{1}{B} \sum_{b=1}^{B} P_b(y = 1 \mid \mathbf{x})$$
The Gini Impurity at node $t$ is defined as:
$$I_G(t) = 1 - \sum_{k=0}^{1} p_k^2$$
where $p_k$ is the fraction of items labeled with class $k$ at node $t$.

### 2.6 Hyperparameter Configuration
- `n_estimators = 100`: Balance between variance reduction and memory footprint.
- `max_depth = 15`: Prevents deep pathological memorization of specific campaign tokens.
- `min_samples_split = 4`: Requires at least 4 samples to split an internal node.
- `min_samples_leaf = 2`: Smooths terminal leaf predictions, avoiding single-sample outliers.
- `class_weight = 'balanced'`: Adjusts sample weights inversely proportional to class frequencies.

### 2.7 Evaluated Performance (Phase 3 Training — 47,074 holdout samples)

| Metric | Value |
|---|---|
| Accuracy | 99.59% |
| Precision (Phishing) | 99.89% |
| Recall (Phishing) | 99.14% |
| F1-Score (Phishing) | 99.52% |
| True Positives | 19,932 |
| True Negatives | 26,949 |
| False Positives | 21 |
| False Negatives | 172 |

Dataset: **PhiUSIIL Phishing URL Dataset** (UCI Repository ID: 967)  
235,370 cleaned samples · 80/20 stratified split · random_state=42

### 2.8 Top Feature Importances (Gini, Random Forest)
1. `uses_https` — 41.88%
2. `path_length` — 16.11%
3. `num_slashes` — 13.23%
4. `domain_path_ratio` — 11.32%
5. `digit_count` — 5.73%

---

## 3. Message Classification Model: TF-IDF + Logistic Regression (Phase 7 — Live Integration)

### 3.1 Why TF-IDF + Logistic Regression?
- **TF-IDF (Term Frequency-Inverse Document Frequency):** Converts variable-length raw text into numerical feature vectors across 3,000 unigram and bigram dimensions with sublinear term scaling. Frequent domain-general English stop words are discounted, while salient threat vocabulary ("urgent", "suspended", "otp", "verify") is boosted.
- **Logistic Regression with Balanced Weights:** Maps log-odds linearly to class probabilities:
$$P(y = 1 \mid \mathbf{x}) = \sigma(\mathbf{w}^T \mathbf{x} + b) = \frac{1}{1 + e^{-(\mathbf{w}^T \mathbf{x} + b)}}$$
- **Interpretability:** Model weights $\mathbf{w}$ represent direct log-odds shifts. Adversarial phrasing carries large positive weights, while benign conversational words carry negative weights.
- **Leakage-Free Validation:** The `TfidfVectorizer` is fitted **strictly on $X_{\text{train}}$** during the 80/20 stratified split; $X_{\text{test}}$ is transformed using the fitted vocabulary without re-estimation.

### 3.2 Dataset Semantics & Ingestion
- **Official Source:** UCI SMS Spam Collection (Almeida & Hidalgo, 2011).
- **Label Semantics:**
  - `ham` $\rightarrow 0 \rightarrow$ **Legitimate/Ham**
  - `spam` $\rightarrow 1 \rightarrow$ **Malicious/Spam**
- **Academic Distinction:** The dataset contains SMS spam and unsolicited scam messages. The model is therefore designated as an **"SMS Spam/Malicious Message Classifier"**, acting as one signal in PhishGuard AI's multi-layered defense when combined with URL analysis and heuristic social engineering indicators.
- **Dynamic Preprocessing Pipeline Accounting:**
  - Raw instances ingested: **5,574**
  - Valid parsed records: **5,574**
  - Duplicate messages dropped dynamically: **414**
  - Final unique cleaned records: **5,160**
    - Legitimate / Ham ($0$): **4,518** (87.56%)
    - Malicious / Spam ($1$): **642** (12.44%)
  - Training Partition (80%): **4,128** samples
  - Holdout Test Partition (20%): **1,032** samples

### 3.3 Holdout Evaluation Metrics (1,032 Test Instances)

| Metric | Value |
|---|---|
| **Accuracy** | **97.77%** |
| **Precision (Malicious/Spam)** | **89.47%** |
| **Recall (Malicious/Spam)** | **92.97%** |
| **F1-Score (Malicious/Spam)** | **91.19%** |
| **True Negatives (TN)** | **890** |
| **False Positives (FP)** | **14** |
| **False Negatives (FN)** | **9** |
| **True Positives (TP)** | **119** |

### 3.4 Dynamic Class Indexing Safety
The model does not assume class 1 is located at array index 1. In `services/message_analyzer.py`, target index lookup is dynamically verified:
```python
classes = list(clf.classes_)
target_idx = classes.index(1)
text_ml_prob = round(float(probs[target_idx]), 4)
```

### 3.5 Composite Message Risk Engine Formulation
To synthesize text semantics, heuristic coercion rules, and embedded links, Mode B employs a 55/25/20 bounded linear combination:
$$\text{Composite Risk} = \min(100, \text{Text\_ML}(55) + \text{Rule\_Indicators}(25) + \text{URL\_Cascade}(20))$$
- **Text ML Contribution (0 to 55 pts):** $\text{round}(p_{\text{malicious}} \times 55)$
- **Rule Indicator Contribution (0 to 25 pts):** $\min(\sum \text{rule.severity\_score}, 25)$
- **URL Cascade Contribution (0 to 20 pts):** $\min(\text{round}(\max(\text{URL Risk}) \times 0.20), 20)$

---

## 4. Evaluation Metrics & Theoretical Definitions

### 4.1 Confusion Matrix Structure
| Actual \ Predicted | Predicted Legitimate ($0$) | Predicted Phishing ($1$) |
| :--- | :--- | :--- |
| **Actual Legitimate ($0$)** | **True Negative (TN)** | **False Positive (FP)** (False Alarm) |
| **Actual Phishing ($1$)** | **False Negative (FN)** (Missed Attack) | **True Positive (TP)** |

### 4.2 Mathematical Formulations
1. **Accuracy:** $\frac{TP + TN}{TP + TN + FP + FN}$
2. **Precision:** $\frac{TP}{TP + FP}$ — How many predicted phishing are truly phishing?
3. **Recall:** $\frac{TP}{TP + FN}$ — How many actual phishing did the model catch?
4. **F1-Score:** $2 \cdot \frac{\text{Precision} \cdot \text{Recall}}{\text{Precision} + \text{Recall}}$

---

## 5. Distinction: ML Probability Estimate vs. Composite Risk Score
- **ML Probability Estimate:** The posterior probability $P(\text{Phishing} \mid \mathbf{x}) \in [0.0, 1.0]$ from the classifier. It is called an *estimate* because it reflects patterns in the training distribution, not an absolute guarantee of maliciousness.
- **Risk Score:** PhishGuard AI's normalized internal index $[0, 100]$ synthesized from both the statistical ML estimate (60% weight) and deterministic cybersecurity indicators (40% weight). This is a **project-defined composite** — not an ISO/NIST standardized metric.

---

## 6. Phase 9 Explainable AI (XAI) Architecture

### 6.1 Design Philosophy: Evidence-Based Transparency
PhishGuard AI's explainability layer adheres to three core tenets:
1. **Traceable to Ground-Truth Evidence:** Every explanation shown to the user corresponds directly to an extracted feature, a triggered deterministic rule, or a mathematically bounded risk contribution. No claims of "AI intuition" are ever made.
2. **Feature Observation vs. Model Attribution:** Extracted features are described as **structural observations** (e.g. *"The URL uses a raw IP address"*), rather than causal claims (avoiding *"This feature caused the model to classify as phishing"*), since random forest feature importances reflect global ensemble weights rather than sample-level attribution.
3. **No Safety Inferences from Transport Encryption:** The observation layer explicitly disclaims that HTTPS implies legitimacy: *"HTTPS confirms encryption only — it does NOT establish that the website is legitimate or trustworthy."*

### 6.2 The 25 URL Feature Observation Mapping
Each of the 25 lexical features extracted in `ml/feature_extractor.py` is mapped via `ml/feature_descriptions.py` into a structured observation with one of three discrete severity levels:
- **`normal`:** Value within standard benign Internet conventions (e.g. single dot in hostname, standard length).
- **`noteworthy`:** Elevated or non-standard metric worth user awareness (e.g. 2 subdomain levels, lack of HTTPS, high entropy).
- **`suspicious`:** Metric strongly correlated with adversarial or deceptive practices (e.g. raw IP hostname, `@` symbol redirection, URL shortener, known disposable TLD).

### 6.3 Global vs. Per-Sample Model Feature Importance
When the Random Forest classifier exposes `feature_importances_`, the top-10 global features are presented in the UI labeled strictly as:
> **GLOBAL MODEL FEATURE IMPORTANCE**
> *"These values reflect the Random Forest model's global feature importance across all training samples. They indicate which features are generally most informative for the classifier. This is NOT a per-sample explanation for this specific URL."*

### 6.4 Dynamic Investigation Timeline
The pipeline records only stages actually traversed:
- **URL Analysis:** Input → Validation & Normalization → Feature Extraction → ML Inference → Rule Evaluation → Risk Calculation → Explanation Assembly.
- **Message Analysis:** Input → Heuristic Indicator Scan → Text ML Inference → (URL Extraction & Cascade if links found) → Composite Risk Calculation → Explanation Assembly.

---

## 7. Known Limitations
- The ML probability is a **statistical estimate** trained on historical data, not a real-time ground truth verdict.
- HTTPS presence does **not** guarantee legitimacy — phishing sites increasingly use TLS certificates.
- A suspicious TLD (`.tk`, `.xyz`) does **not** alone prove phishing — many legitimate sites use these TLDs.
- Static lexical analysis cannot detect phishing sites that dynamically redirect after the first visit.
- The model may underperform on novel phishing campaign structures not represented in the training corpus (zero-day attacks).
- Risk score thresholds (Low/Medium/High/Critical) are **project-defined** and should not be cited as universal cybersecurity standards.
- Global feature importances reflect dataset-wide variance reduction; they do not quantify individual per-sample attribution (SHAP/LIME are out of scope for Phase 9).
