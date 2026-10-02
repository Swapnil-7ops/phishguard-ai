# PhishGuard AI - Comprehensive PBL Viva Examination Guide (55 Q&A)

This document prepares BE Information Technology students for oral viva defense, project evaluations, and technical questioning.

---

### Category 1: Cybersecurity & Phishing Fundamentals (Q1 – Q8)

#### Q1: What is phishing, and how does it differ from other cyber attacks?
**Answer:** Phishing is a form of social engineering where an adversary impersonates a trustworthy entity (banks, tech companies, logistics services) to deceive victims into divulging sensitive credentials, financial data, or session tokens. Unlike purely software vulnerabilities (e.g. buffer overflows or SQL injection), phishing exploits human psychology (urgency, fear, curiosity).

#### Q2: What are the primary modern delivery vectors for phishing?
**Answer:**
1. **Email Phishing:** Spoofed corporate communications directing users to replica login portals.
2. **Smishing (SMS Phishing):** Text messages claiming delivery failures or account locks.
3. **Vishing (Voice Phishing):** Phone calls pretending to be bank fraud prevention.
4. **Quishing (QR Code Phishing):** Physical or digital QR codes masking deceptive URLs.
5. **Spear Phishing / BEC:** Highly targeted attacks against high-profile individuals.

#### Q3: Why is HTTPS alone insufficient to determine whether a website is legitimate?
**Answer:** HTTPS only guarantees cryptographic encryption in transit between the browser and the server, protecting against eavesdropping (Man-in-the-Middle). It does **not** validate the moral integrity or organizational identity of the website owner. Free, automated Certificate Authorities (e.g. Let's Encrypt) allow threat actors to generate valid TLS certificates for malicious domains in seconds.

#### Q4: What is typosquatting, and how do attackers use it?
**Answer:** Typosquatting (URL hijacking) is the registration of domains that look nearly identical to popular brands, relying on typing mistakes or visual similarity (e.g. `g00gle.com`, `paypa1.com`, `chase-security.com`).

#### Q5: What is an `@` symbol attack in a URL?
**Answer:** According to RFC 3986, the `@` character delimits user authentication credentials from the actual host. In a URL like `http://www.google.com@evil-domain.com/`, web browsers treat `www.google.com` as user information and silently connect to `evil-domain.com`.

#### Q6: Why do threat actors host phishing sites directly on raw IP addresses?
**Answer:** Hosting on raw IPs (e.g., `http://192.168.1.100/login`) allows attackers to bypass domain name registration costs, skip DNS propagation delays, and avoid domain-based reputation blacklists. Legitimate consumer web services almost never present raw IPs to end users.

#### Q7: What is Quishing, and why is it challenging for traditional mail filters?
**Answer:** Quishing is phishing delivered via QR codes. Email security gateways scan text hyperlinks and attachments. When a link is rendered as an image matrix (QR code), standard text filters do not see the URL unless they incorporate Optical Character Recognition (OCR) and 2D barcode decoding libraries like `pyzbar`.

#### Q8: What is Server-Side Request Forgery (SSRF), and how does PhishGuard AI prevent it?
**Answer:** SSRF occurs when an attacker inputs a URL causing the backend server to make internal network requests (e.g., fetching AWS metadata `http://169.254.169.254` or internal LAN IPs). PhishGuard AI prevents SSRF by analyzing URLs **purely through lexical parsing and string feature extraction**; the server NEVER initiates socket connections or fetches remote HTML content.

---

### Category 2: Machine Learning & Feature Engineering (Q9 – Q20)

#### Q9: Why use Machine Learning instead of maintaining a static blacklist of phishing URLs?
**Answer:** Static blacklists (like Google Safe Browsing or PhishTank) suffer from zero-hour latency—it takes hours or days for human analysts to verify and publish a reported phishing URL. Attackers use fast-flux DNS and disposable domains lasting only a few hours. Machine Learning models evaluate structural patterns to detect novel, previously unseen phishing URLs in real time.

#### Q10: Why did you choose Random Forest Classifier as your primary URL model?
**Answer:**
1. Handles non-linear feature interactions without manual polynomial transformations.
2. Robust to outliers and noise through ensemble bagging.
3. Provides Gini feature importance for interpretability.
4. Requires no feature scaling (normalization/standardization).
5. Fast inference time ($< 2\text{ms}$), ideal for REST API serving.

#### Q11: How does a Random Forest construct its ensemble of trees?
**Answer:** Random Forest builds $B$ decision trees using two randomization techniques:
1. **Bootstrap Aggregating (Bagging):** Each tree is trained on a random sample drawn with replacement from the training set.
2. **Feature Subsampling:** At each node split, only a random subset of features ($\sqrt{p}$) is evaluated, decorrelating individual trees and reducing ensemble variance.

#### Q12: What is Gini Impurity, and how is it used in Decision Trees?
**Answer:** Gini Impurity measures the probability of incorrectly classifying a randomly chosen element if it were randomly labeled according to the class distribution.
$$I_G(t) = 1 - \sum_{k=0}^{1} p_k^2$$
A node split is chosen to maximize the Gini Gain (reduction in impurity).

#### Q13: How is Feature Importance calculated in a Random Forest?
**Answer:** In scikit-learn, Feature Importance is calculated as the **Mean Decrease in Impurity (MDI)**. For each feature, the total decrease in Gini impurity across all nodes where that feature was chosen to split is computed, averaged across all 100 trees, and normalized to sum to 1.0.

#### Q14: Explain what Shannon Entropy measures in a URL hostname.
**Answer:** Shannon Entropy measures the randomness or information content of characters in a string:
$$H(X) = -\sum_{i} P(x_i) \log_2 P(x_i)$$
Legitimate hostnames (e.g. `google`, `wikipedia`) consist of dictionary words with low entropy ($< 2.8$). Domain Generation Algorithms (DGAs) used in phishing and malware generate randomized alphanumeric strings (e.g. `x9q8m2z1k4`) which exhibit high entropy ($> 3.8$).

#### Q15: Why is `domain_path_ratio` an informative feature?
**Answer:** Legitimate corporate websites typically maintain concise path hierarchies. Phishers frequently create deep folder hierarchies (e.g. `/secure/chase/online/login/verification/session/auth.php`) to pad the URL, pushing the suspicious root domain out of view on mobile screens.

#### Q16: How do you handle missing values or unparseable URLs during feature extraction?
**Answer:** `ml/feature_extractor.py` wraps `urlparse` in a try-except block. If parsing fails completely or input is empty, it returns a deterministic 25-feature dictionary with all numerical values set to 0.

#### Q17: What is the risk of training on duplicate URLs?
**Answer:** Duplicate URLs cause data leakage between train and test sets if the same URL appears in both partitions. This causes overly optimistic, inflated evaluation metrics. `ml/train_url_model.py` explicitly executes `df.drop_duplicates(subset=['url'])` prior to splitting.

#### Q18: What is a Stratified Train/Test Split, and why is it necessary?
**Answer:** Stratification ensures that the training and test sets maintain the exact same proportion of class labels ($y=0$ vs $y=1$) as the original dataset. Without stratification, a random split could underrepresent the minority phishing class in the test set, skewing evaluation.

#### Q19: What techniques did you implement to prevent the Random Forest from overfitting?
**Answer:**
1. `max_depth = 15`: Prevents trees from growing infinitely deep.
2. `min_samples_split = 4`: Prohibits splitting nodes with fewer than 4 instances.
3. `min_samples_leaf = 2`: Requires terminal leaves to contain at least 2 samples.
4. Ensemble bagging across 100 trees.

#### Q20: Why do you persist the feature column ordering in `feature_config.json`?
**Answer:** Machine learning models identify features by column index, not by name. If the dictionary keys change order during live inference, the feature vector would map to the wrong decision tree branch nodes, yielding corrupt predictions. Saving `feature_names` guarantees that training and inference vectors align identically.

---

### Category 3: NLP & Message Classification (Q21 – Q28)

#### Q21: What is TF-IDF, and how is it calculated?
**Answer:** TF-IDF stands for Term Frequency - Inverse Document Frequency.
$$\text{TF-IDF}(t, d, D) = \text{TF}(t, d) \times \log\left(\frac{1 + |D|}{1 + |\{d \in D : t \in d\}|}\right) + 1$$
It rewards words that appear frequently within a specific message ($\text{TF}$) while penalizing common English words that appear across all messages ($\text{IDF}$).

#### Q22: Why did you choose Logistic Regression instead of deep learning (e.g. BERT) for message analysis?
**Answer:**
1. **Explainability:** Logistic Regression coefficients are directly interpretable—positive weights correspond to phishing vocabulary, allowing clear viva demonstration.
2. **Resource Efficiency:** Runs locally on standard student CPU hardware in milliseconds without GPU dependencies.
3. **Sparse Matrix Handling:** Works natively with high-dimensional TF-IDF vectors.

#### Q23: How does Logistic Regression convert linear dot products into probabilities?
**Answer:** Using the Sigmoid (Logistic) activation function:
$$\sigma(z) = \frac{1}{1 + e^{-z}}$$
where $z = \mathbf{w}^T \mathbf{x} + b$. This maps any real number into the bounded probabilistic interval $(0, 1)$.

#### Q24: What social engineering indicators does your system detect in text messages?
**Answer:**
1. Urgency / Time pressure (`immediate`, `within 24 hours`).
2. Account suspension / Threat language (`suspended`, `locked`, `legal action`).
3. Credential requests (`verify password`, `update login`).
4. OTP interception (`enter OTP`, `verification code`).
5. Payment / financial demands (`unpaid fee`, `wire transfer`).
6. Brand impersonation (`PayPal`, `Chase`, `Amazon`).
7. Excessive capitalization (all-caps urgency).

#### Q25: How does the system extract URLs from messages?
**Answer:** `services/message_analyzer.py` uses regular expressions matching RFC-compliant web URI patterns (`https?://[a-zA-Z0-9.-]+...`). Extracted links are returned in the response and automatically cascaded into the URL Analyzer.

#### Q26: What is Cascaded Link Analysis?
**Answer:** When an email or SMS is submitted, the message analyzer extracts any embedded URLs and automatically runs the 25-feature URL analyzer on them. If an extracted link is classified as Critical Phishing, the message's overall risk score is proportionally elevated.

#### Q27: How does n-gram range `(1, 2)` benefit text classification?
**Answer:** An n-gram range of `(1, 2)` extracts both single words (unigrams, e.g. "password", "urgent") and adjacent word pairs (bigrams, e.g. "verify account", "account suspended"). Bigrams capture contextual phrases that single words miss.

#### Q28: How is user privacy handled when analyzing sensitive email content?
**Answer:** `config.py` contains `STORE_RAW_CONTENT=false`. When disabled, the original message text is masked as `"[Content masked for privacy]"` before writing to MongoDB, while preserving statistical metrics for analytics.

---

### Category 4: Evaluation Metrics & Validation (Q29 – Q36)

#### Q29: In phishing detection, which error is more dangerous: False Positive or False Negative?
**Answer:** A **False Negative (FN)** is significantly more dangerous. A False Negative means the system misclassified an active phishing attack as legitimate, leading the user to enter credentials and suffer identity theft or financial loss. A False Positive (FP) is a false alarm that inconveniences the user by warning them about a safe site.

#### Q30: What is the difference between Precision and Recall?
**Answer:**
- **Precision:** $\frac{TP}{TP + FP}$ — "When the model claims a URL is phishing, how often is it right?"
- **Recall:** $\frac{TP}{TP + FN}$ — "Out of all actual phishing URLs in existence, what percentage did the model detect?"

#### Q31: Why is Accuracy alone misleading on imbalanced datasets?
**Answer:** If a dataset contains 95% legitimate URLs and 5% phishing URLs, a naive model that predicts "Legitimate" for every URL achieves 95% accuracy while having a 0% recall on phishing attacks. Precision, Recall, and F1-score provide an honest evaluation.

#### Q32: What is the F1-Score, and why is it the harmonic mean instead of arithmetic mean?
**Answer:** F1-score is $2 \cdot \frac{\text{Precision} \cdot \text{Recall}}{\text{Precision} + \text{Recall}}$. The harmonic mean penalizes extreme imbalances: if either Precision or Recall is close to zero, the F1-score drops close to zero, unlike the arithmetic mean which would average out to 50%.

#### Q33: How is your model evaluated? Are the numbers hardcoded?
**Answer:** The metrics are **never hardcoded**. `ml/train_url_model.py` executes training on a stratified holdout test split and writes the computed scikit-learn results directly to `models/evaluation_results.json`. The web dashboard reads and visualizes this exact JSON file via the `GET /api/model-metrics` endpoint.

#### Q34: What is the difference between Model Confidence and Risk Score?
**Answer:**
- **Model Confidence:** The posterior probability $P(y=1|\mathbf{x})$ generated by the Random Forest classifier based solely on statistical feature weights.
- **Risk Score:** PhishGuard AI's composite 0–100 index blending ML confidence (60% weight) and deterministic security rule violations (40% weight).

#### Q35: What does the Confusion Matrix tell you about your classifier?
**Answer:** It provides the exact count breakdown of True Positives, True Negatives, False Positives, and False Negatives on the holdout evaluation set.

#### Q36: How does `joblib` differ from Python's standard `pickle`?
**Answer:** `joblib` is optimized specifically for scikit-learn estimators and NumPy arrays, utilizing memory mapping to load large multi-tree ensembles significantly faster than standard `pickle`.

---

### Category 5: Architecture, Flask & Database (Q37 – Q44)

#### Q37: Why is the Flask application organized using the Application Factory pattern?
**Answer:** `app.py` defines `create_app()`. The application factory pattern separates app instantiation from execution, enables clean Blueprint registration, avoids circular imports, and allows automated test suites (`tests/test_api.py`) to create isolated test clients.

#### Q38: What are Flask Blueprints, and why are they used?
**Answer:** Blueprints organize routes into modular components (`routes/url_routes.py`, `routes/message_routes.py`, `routes/scan_routes.py`, `routes/dashboard_routes.py`). This prevents monolithic `app.py` files and adheres to clean separation of concerns.

#### Q39: How does the MongoDB in-memory fallback mechanism work?
**Answer:** `database/mongodb.py` attempts a connection to `MONGO_URI` with a 2-second timeout. If the MongoDB daemon is offline, it logs a warning and stores records in a Python memory queue (retaining the last 1,000 scans). All route calls execute identically without 500 server crashes.

#### Q40: What MongoDB indexes are created, and why?
**Answer:**
1. `{"timestamp": -1}`: Optimizes chronological queries for recent history.
2. `{"prediction": 1}`: Speeds up aggregation pipelines computing threat distributions.
3. `{"input_type": 1}`: Optimizes filtering by vector (URL vs Message vs QR).

#### Q41: How does the client-side JavaScript communicate with the backend?
**Answer:** Through asynchronous `fetch()` API calls to REST endpoints (`POST /api/analyze-url`, `GET /api/dashboard-stats`), sending and receiving JSON payloads.

#### Q42: What role does Chart.js play in the dashboard?
**Answer:** Chart.js renders responsive vector graphics on HTML5 canvas elements, displaying:
1. Threat classification doughnut chart.
2. 7-day scan activity timeline.
3. Horizontal bar chart of top triggered security indicators.

#### Q43: What file upload security restrictions are enforced for QR and Screenshot analysis?
**Answer:**
1. Allowed extension check (`.png`, `.jpg`, `.jpeg`, `.webp`).
2. Maximum size ceiling (`MAX_CONTENT_LENGTH = 10MB`) to mitigate Denial of Service (DoS).
3. Secure in-memory byte buffer inspection via `io.BytesIO` rather than executing arbitrary files.

#### Q44: Why is the LLM integration optional?
**Answer:** A student examination project must function independently without depending on paid cloud APIs or internet connectivity. The core detection engine is fully contained within the local scikit-learn models and rule engine.

---

### Category 6: Explainability, Limitations & Viva Defense (Q45 – Q55)

#### Q45: What is Explainable AI (XAI), and why is it essential in cybersecurity?
**Answer:** XAI refers to methods that make machine learning decisions transparent and understandable to humans. In cybersecurity, black-box predictions are dangerous: a security analyst cannot blindly block a corporate domain without knowing *why*. PhishGuard AI provides exact feature rankings, triggered rules, and transparent mathematical formulas for every score.

#### Q46: What is the exact formula for the composite Risk Score?
**Answer:**
$$\text{Risk Score} = \min(100, \text{round}(\text{ML\_Probability} \times 60) + \min(\sum \text{Rule\_Scores}, 40))$$
- 60% of the score is governed by the statistical ML classifier.
- 40% of the score is governed by deterministic rule violations (capped at 40).

#### Q47: Can an attacker evade your 25-feature URL model? If so, how?
**Answer:** Yes. An attacker could purchase an aged, high-reputation expired domain, host the phishing form on a short path (`/login`), and avoid using hyphens or IP addresses. This is why multi-layered defense (combining URL features, message text heuristics, and domain age) is required.

#### Q48: What is Fast-Flux DNS, and does your system detect it?
**Answer:** Fast-flux DNS is a technique where attackers rapidly change the A records of a domain to hundreds of different IP addresses within minutes to evade IP-based blacklisting. Because PhishGuard AI focuses on lexical URL structure rather than active DNS polling, detecting fast-flux would require external DNS query integrations (documented in Future Scope).

#### Q49: What is the difference between supervised and unsupervised learning?
**Answer:**
- **Supervised Learning:** The model is trained on labeled pairs $(\mathbf{x}, y)$ where the true ground truth (0 = legitimate, 1 = phishing) is provided. Used in PhishGuard AI.
- **Unsupervised Learning:** The algorithm clusters unlabeled data based purely on intrinsic mathematical similarities (e.g. K-Means, Isolation Forests).

#### Q50: How would you deploy PhishGuard AI into production?
**Answer:**
1. Run behind a production WSGI server like **Gunicorn** or **Waitress** with multiple worker processes.
2. Place behind a reverse proxy like **Nginx** for SSL termination, rate limiting, and static file caching.
3. Deploy inside a containerized **Docker** container for reproducible environment dependencies.

#### Q51: What is data drift in machine learning, and how does it affect phishing detection?
**Answer:** Data drift (or concept drift) occurs when the statistical properties of the target variable change over time. In phishing, attackers invent new TLD strategies and obfuscation patterns not present in older training sets. To maintain accuracy, the model must be periodically retrained on fresh threat feeds.

#### Q52: Why is the project called "Multi-Modal"?
**Answer:** It accepts and processes multiple distinct input modalities: plain URLs (Mode A), natural language text/SMS (Mode B), 2D barcode imagery (Mode C), and raster screenshots (Mode D).

#### Q53: What would you answer if the examiner asks: "Can this tool replace antivirus or firewall software?"
**Answer:** No. PhishGuard AI is an application-layer decision-support system specifically focused on detecting social engineering and deceptive link structures. It does not inspect network packets, monitor endpoint process memory, or analyze compiled malware binaries like antivirus/EDR software.

#### Q54: What is the difference between a False Alarm and a Missed Detection?
**Answer:** A False Alarm is a False Positive (benign classified as phishing). A Missed Detection is a False Negative (phishing classified as benign). In security systems, balancing these two errors represents the fundamental ROC/AUC trade-off.

#### Q55: What are the three most impactful future improvements for this project?
**Answer:**
1. A Chrome WebExtension for real-time browsing protection.
2. Real-time WHOIS domain age inspection (flagging domains registered $< 30$ days ago).
3. Sandboxed headless browser rendering to analyze dynamic client-side JavaScript.

---

### Category 6: Database, Persistence & Telemetry (Q56 – Q65)

#### Q56: Why did you use MongoDB?
**Answer:** MongoDB is a document-oriented NoSQL database that stores data in flexible BSON (JSON-like) format. Unlike relational databases requiring strict tabular schemas and schema migrations, MongoDB natively supports polymorphic document structures, nested feature dictionaries, and variable-length arrays of triggered rules and indicators.

#### Q57: Why is MongoDB suitable for scan history?
**Answer:**
1. **Hierarchical Data Representation:** Each scan record contains nested objects (`features`, `triggered_rules`, `ml`) that map directly to JSON without complex table joins.
2. **High Write Throughput:** Document insertions are fast, minimizing API response latency when recording investigations.
3. **Flexible Querying & Indexing:** Provides fast multi-field filtering by vector type, prediction verdict, and risk tier alongside descending chronological sorting.

#### Q58: What is PyMongo?
**Answer:** PyMongo is the official, high-performance Python distribution client for MongoDB. It provides idiomatic Python dictionary mapping, connection pooling, and resilient server-selection timeout configuration (`serverSelectionTimeoutMS`).

#### Q59: What happens if MongoDB is unavailable?
**Answer:** PhishGuard AI implements a zero-crash resilient fallback pattern. During startup and runtime write attempts, if the MongoDB daemon is unreachable (e.g. timeout exceeds 2.0 seconds), the system automatically activates an in-memory ring-buffer queue (`_MEMORY_STORAGE`). The web application continues functioning normally without throwing unhandled 500 exceptions or Python stack traces.

#### Q60: Why do you need indexes?
**Answer:** Without indexes, MongoDB must perform a collection scan (checking every document on disk). Indexes create ordered B-tree data structures allowing sub-millisecond lookups. PhishGuard AI creates indexes on:
1. `timestamp` (-1): For chronological sorting, pagination (`skip`/`limit`), and 7-day timeline queries.
2. `scan_type` (1): For filtering URL vs. message scans.
3. `prediction` (1): For categorical threat aggregations.
4. `risk_level` (1): For risk tier filtering.

#### Q61: How does dashboard aggregation work?
**Answer:** `get_dashboard_statistics()` queries stored records to dynamically compute:
1. Total scan count across all vectors.
2. Prediction distribution counts (`Phishing`, `Suspicious`, `Legitimate`).
3. Risk level distribution counts (`Low`, `Medium`, `High`, `Critical`).
4. Average composite risk score across investigations.
5. 7-day rolling scan activity timeline.
6. Top triggered security indicators sorted by frequency.
Both MongoDB and the in-memory fallback use the exact same calculation logic, guaranteeing consistent telemetry without fabricated numbers.

#### Q62: How do you prevent duplicate scan records?
**Answer:**
1. **Frontend Debouncing:** Submit buttons are immediately disabled upon form submission (`submitBtn.disabled = true`), and re-entrant submission flags (`isAnalyzingUrl`, `isAnalyzingMsg`) block rapid double-clicks or repeated keyboard submits.
2. **Clean Lifecycle:** An investigation scan record is only inserted into the database after analysis successfully concludes. Failed client validation (e.g. empty inputs or illegal URI schemes) never creates audit records.

#### Q63: How do you protect sensitive scan data?
**Answer:**
1. **Privacy Redaction Layer:** Prior to persistence, `database/privacy.py` strips embedded passwords from URL authorities (`http://user:[REDACTED]@host`) and scrubs sensitive query parameters (`token`, `api_key`, `secret`, `jwt`).
2. **Message Scrubbing:** Regular expression filters redact passwords, OTP codes, credit/debit card numbers, and Bearer tokens from stored message copies.
3. **In-Memory Separation:** Analysis is executed on the original input in memory; sanitization is applied strictly to the persisted document copy.
4. **Zero-Raw Storage Mode:** Setting `STORE_RAW_CONTENT=false` replaces all text bodies with a generic privacy placeholder.

#### Q64: Why should URLs never be fetched by the analyzer?
**Answer:** Initiating remote network connections to user-submitted URLs creates critical security hazards:
1. **Server-Side Request Forgery (SSRF):** Attackers could submit internal metadata URLs (`http://169.254.169.254/`) or intranet IPs (`http://192.168.1.1/admin`) to scan and compromise backend infrastructure.
2. **Drive-by Malware Delivery:** Fetching remote content could download malicious executables or trigger remote code vulnerabilities.
3. **Attacker Notification:** Contacting a targeted phishing site alerts the attacker that their campaign is being actively investigated, allowing them to burn and rotate domains. PhishGuard AI analyzes URLs purely as static text strings.

#### Q65: What is the difference between persistent storage and in-memory fallback?
**Answer:**
- **Persistent Storage (MongoDB):** Writes BSON records to disk. Data survives web server reboots, application upgrades, and power cycles. Enables multi-session audit compliance.
- **In-Memory Fallback:** Maintains records in a Python list queue in RAM. Provides high speed and zero external setup for demonstration environments, but records are volatile and clear when the Python process terminates.
