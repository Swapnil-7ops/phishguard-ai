# PhishGuard AI

## Explainable AI-Based Multi-Modal Phishing Detection System
*Academic Programming Based Learning (PBL) Project — Bachelor of Engineering (Information Technology)*

---

## 1. Project Title
**PhishGuard AI: Explainable AI-Based Multi-Modal Phishing Detection System**

---

## 2. Problem Statement
Phishing remains the single most prevalent attack vector initiating cybersecurity breaches, identity theft, ransomware deployments, and unauthorized financial wire transfers. Conventional defense techniques rely on signature blacklists (e.g., Google Safe Browsing, PhishTank), which suffer from significant zero-hour latency—often taking 12 to 48 hours to discover and catalog newly spun-up malicious domains. Meanwhile, emerging deep learning models operate as opaque "black boxes," leaving Security Operations Center (SOC) analysts and end users without transparent explanations for why a link or communication was flagged.

---

## 3. Motivation
In modern engineering environments, cybersecurity tooling must be **accurate, explainable, and multi-modal**. Users encounter deceptive links across diverse surfaces: web links, SMS smishing texts, WhatsApp alerts, and physical QR codes (quishing). PhishGuard AI addresses these multi-vector threats by unifying statistical Machine Learning with deterministic rule heuristics, transparent mathematical scoring, and multi-modal ingestion.

---

## 4. Objectives
1. Implement a genuine supervised Machine Learning pipeline utilizing `RandomForestClassifier` trained on 25 lexical and structural URL features.
2. Formulate a deterministic security rule engine detecting critical indicators (raw IP hostnames, `@` credential redirects, disposable TLDs, and URL shorteners).
3. Build an NLP text analyzer using TF-IDF and Logistic Regression to detect social engineering urgency, threat language, and OTP harvesting.
4. Provide a Quishing (QR code) optical decoding pipeline and an optional multimodal vision screenshot inspector.
5. Derive an explainable, transparent 0–100 composite **Risk Score** distinguishing statistical Model Confidence from composite security risk.
6. Maintain an audit trail with MongoDB and resilient in-memory fallback.
7. Deliver a professional, dark cybersecurity dashboard with Chart.js analytics.

---

## 5. Features
- **Mode A (URL Analyzer):** Deterministic 25-feature extraction, Random Forest inference, rule evaluation, and explainability breakdown.
- **Mode B (Message Analyzer):** NLP linguistic heuristics, TF-IDF classification, and automatic hyperlink extraction with cascaded URL evaluation.
- **Mode C (QR Code Quishing Scanner):** Decodes 2D barcode images and feeds extracted endpoints into the URL pipeline without visiting the link.
- **Mode D (Screenshot / Visual Phishing Detector):** Lightweight OpenCV contour heuristics and optional OCR text keyword extraction detect fake login forms and brand mismatches entirely in-memory with zero outbound network access.
- **Mode E (Email Phishing Analyzer - .EML):** Full RFC 5322 MIME email parsing, header forensics, Authentication-Results inspection (SPF/DKIM/DMARC), subject social engineering triggers, safe HTML text stripping, URL extraction with cascaded analysis, and attachment metadata inspection with zero payload execution.
- **Explainable Scoring Engine:** Full mathematical breakdown displaying how evidence domains (ML probability, rule impacts, header anomalies, threat intel) form the final 0–100 index.
- **Real-Time Analytics Dashboard:** Displays total scans, threat classification distributions, 7-day timeline trends, and top triggered rules via Chart.js.
- **Audit History & JSON Export:** Searchable investigation audit logs with single-click JSON export.
- **Zero-Crash In-Memory Fallback:** The application operates seamlessly even if local MongoDB daemons are offline.

---

## 6. Technology Stack
- **Frontend:** HTML5, CSS3 (Retro-Modern Editorial Cybersecurity Theme), Vanilla JavaScript, Chart.js 4.4.
- **Backend:** Python 3.10+, Flask 3.0+, REST API Architecture.
- **Email Parser:** Python standard library `email` (RFC 5322 MIME engine) & `html.parser`.
- **Machine Learning:** scikit-learn, pandas, NumPy, joblib.
- **NLP:** scikit-learn (TfidfVectorizer + LogisticRegression).
- **Database:** MongoDB via PyMongo (with transparent in-memory ring buffer fallback).
- **Computer Vision & Utilities:** OpenCV (cv2), Pillow (PIL), pytesseract (optional OCR wrapper), tldextract, python-dotenv.
- **Optional Threat Intelligence:** VirusTotal v3 API.

---

## 7. System Architecture
```
[User Interface]
       │ (REST HTTP / JSON)
       ▼
[Flask Application Layer (app.py)]
       ├── /api/analyze-url ────────► [25-Feature Extractor] ──► [Random Forest ML] ┐
       │                                                                            ├─► [Risk Engine (0-100)]
       │                              [Deterministic Rule Engine] ───────────────── ┘          │
       ├── /api/analyze-message ────► [NLP Heuristics + TF-IDF] ──► [Link Extraction]          │
       ├── /api/analyze-qr ─────────► [OpenCV QR Decoder] ───────► [Pipelined URL Mode]        │
       ├── /api/analyze-screenshot ─► [OpenCV Contours + OCR] ───► [Pipelined URL Mode]        │
       └── /api/analyze-email ──────► [MIME Headers + Auth + Body] ─► [Pipelined URL Mode]     ▼
                                                                                     [MongoDB / Fallback]
```


---

## 8. ML Methodology
- **Classification Paradigm:** Binary supervised classification ($y \in \{0, 1\}$).
- **Algorithm Choice:** `RandomForestClassifier` (100 trees, `max_depth=15`, `class_weight='balanced'`).
- **Feature Selection:** 25 lexical and structural URL attributes.
- **Overfitting Mitigation:** Stratified 80/20 train/test split, `min_samples_split=4`, `min_samples_leaf=2`.
- **Message NLP Classifier:** TF-IDF unigram and bigram representation with balanced Logistic Regression.

---

## 9. Dataset
- **URL Corpus (`data/datasets/phishing_urls.csv`):** Verified balanced collection of authentic web services and verified adversarial phishing vectors.
- **Message Corpus (`data/datasets/phishing_messages.csv`):** Real-world SMS and email smishing and legitimate correspondence templates.
- **Automated Generator:** Run `python data/datasets/prepare_dataset.py` to regenerate or verify the dataset.

---

## 10. Feature Engineering (25 Dimensions)
1. `url_length`: Total character count
2. `hostname_length`: FQDN character count
3. `path_length`: Subdirectory path depth
4. `query_length`: Query string character count
5. `num_dots`: Period frequency
6. `num_hyphens`: Brand-spoofing hyphen frequency
7. `num_underscores`: Underscore count
8. `num_slashes`: Directory hierarchy slashes
9. `num_question_marks`: Parameter delimiter count
10. `num_equal_signs`: Parameter assignment count
11. `num_ampersands`: Parameter separator count
12. `num_percent`: Hex encoding percentage signs
13. `has_at_symbol`: RFC 3986 `@` credential spoofing
14. `has_ip_address`: Raw IPv4 or IPv6 hostname
15. `uses_https`: Transport encryption flag
16. `num_subdomains`: Nested subdomain count
17. `suspicious_keyword_count`: Frequency of credential-harvesting tokens
18. `is_url_shortener`: Known link shortener matching
19. `hostname_entropy`: Shannon character entropy (DGA marker)
20. `digit_count`: Total numeric digits
21. `special_char_count`: Non-alphanumeric character count
22. `domain_path_ratio`: Path length relative to domain length
23. `has_suspicious_tld`: High-abuse top-level domain flag
24. `encoded_char_count`: Frequency of `%XX` hex sequences
25. `has_double_slash_path`: Open-redirect double-slash marker

---

## 11. Algorithm
The Random Forest constructs an ensemble of 100 decorrelated decision trees using Bootstrap Aggregation (Bagging) and random feature subsampling ($\sqrt{25} = 5$ candidate features per node split). The posterior probability is averaged across all trees:
$$\hat{p}(y = 1 \mid \mathbf{x}) = \frac{1}{100} \sum_{b=1}^{100} P_b(y = 1 \mid \mathbf{x})$$

---

## 12. Training Process
Execute the complete offline training pipeline with:
```bash
python data/datasets/prepare_dataset.py
python ml/train_url_model.py
python ml/train_text_model.py
```
This generates:
- `models/url_model.pkl`
- `models/text_model.pkl`
- `models/text_vectorizer.pkl`
- `models/feature_config.json`
- `models/evaluation_results.json`
- `models/text_evaluation_results.json`

---

## 13. Evaluation Metrics
Evaluated on holdout test partitions (20% stratified split):
- **Accuracy:** Overall correctness across holdout samples.
- **Precision:** True Positives / (True Positives + False Positives).
- **Recall (Sensitivity):** True Positives / (True Positives + False Negatives).
- **F1-Score:** Harmonic mean balancing Precision and Recall.
- **Confusion Matrix:** Explicit counts of TN, FP, FN, TP.

---

## 14. API Documentation
- `POST /api/analyze-url`: Evaluates target URL string.
- `POST /api/analyze-message`: Scans message text, extracts links, scores risk.
- `POST /api/analyze-qr`: Decodes QR code image and pipelines URL.
- `POST /api/analyze-screenshot`: Multimodal vision inspection.
- `GET /api/history`: Paginated historical scan records.
- `GET /api/dashboard-stats`: Chart.js metrics and aggregated tallies.
- `GET /api/model-metrics`: Verifiable offline model metrics.
- `GET /api/health`: Service diagnostic status.

*(See `docs/api_documentation.md` for full schema and examples).*

---

## 15. Database Design
- **Engine:** MongoDB (`phishguard` database, `scans` collection).
- **Indexes:** `timestamp: -1`, `prediction: 1`, `input_type: 1`.
- **Resilient Fallback:** 1,000-element in-memory ring buffer if MongoDB is inactive.
- **Privacy Mode:** `STORE_RAW_CONTENT=false` masks sensitive message text.

---

## 16. Installation
```bash
# Clone or navigate to the directory
cd phishguard-ai

# Install Python dependencies
pip install -r requirements.txt
```

---

## 17. Environment Variables
Copy `.env.example` to `.env`:
```env
MONGO_URI=mongodb://localhost:27017/
DATABASE_NAME=phishguard
FLASK_SECRET_KEY=phishguard-dev-secret-key-2026
DEBUG=True
PORT=5000
STORE_RAW_CONTENT=true
LLM_PROVIDER=gemini
OPENAI_API_KEY=
GEMINI_API_KEY=
```
*(All LLM and MongoDB variables are completely optional).*

---

## 18. Running the Project
```bash
# Step 1: Prepare datasets and train the models
python data/datasets/prepare_dataset.py
python ml/train_url_model.py
python ml/train_text_model.py

# Step 2: Run automated test suite
pytest -v

# Step 3: Launch the web application
python app.py
```
Open your browser at: **`http://localhost:5000`**

---

## 19. User Interface Overview
- **Dashboard (`/dashboard`):** Threat summary cards, classification doughnut chart, 7-day trend line, top indicators bar chart.
- **URL Analyzer (`/url-analyzer`):** Interactive URL scanner with animated risk gauge, verdict badge, triggered rules list, 25-feature matrix, and explainability breakdown.
- **Message Analyzer (`/message-analyzer`):** Social engineering text scanner with automatic URL extraction and cascaded analysis.
- **QR Scanner (`/qr-scanner`):** Drag-and-drop QR code decoder with pipelined safety inspection.
- **Screenshot Vision (`/screenshot-analyzer`):** Multimodal visual inspection for deceptive login dialogs.
- **Model Performance (`/model-performance`):** Real-time confusion matrix and Gini feature importance bars loaded directly from trained artifacts.
- **About & Viva (`/about`):** Comprehensive student viva guide and architecture reference.

---

## 20. Limitations
- **No Remote Network Fetching:** The system does not download HTML or execute remote JavaScript to prevent SSRF and server infection.
- **HTTPS Prevalence:** Over 85% of modern phishing domains use valid SSL certificates; HTTPS is not a standalone proof of safety.
- **Zero-Day Mutations:** Newly registered benign-looking domains may evade lexical filters.
- **Decision-Support Tool:** The output represents an advisory threat index, not absolute legal proof.

---

## 21. Future Scope
- Chrome/Firefox WebExtension for real-time browsing protection.
- WHOIS domain age inspection (flagging domains $< 30$ days old).
- Isolated container sandboxing for headless browser DOM rendering.
- Multilingual transformer (mBERT) fine-tuning for regional smishing detection.

---

## 22. Ethical & Security Considerations
- **Responsible Disclosure:** PhishGuard AI is an educational defense system designed to protect users against cyber deception.
- **Safe Testing:** Demonstration chips utilize harmless synthetic and illustrative URLs.
- **Privacy Protection:** User-submitted email contents can be masked from storage by setting `STORE_RAW_CONTENT=false`.
