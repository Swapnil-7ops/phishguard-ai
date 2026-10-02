/**
 * analyzer.js - Handlers for URL, Message, QR, and Screenshot Analysis
 */

// ==========================================
// 1. URL ANALYZER
// ==========================================
function setupUrlAnalyzer() {
  const form = document.getElementById('url-form');
  if (!form) return;

  // Demo buttons
  document.querySelectorAll('.url-demo-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const input = document.getElementById('url-input');
      input.value = btn.getAttribute('data-url');
      form.dispatchEvent(new Event('submit'));
    });
  });

  // Clear button
  const clearBtn = document.getElementById('url-clear-btn');
  if (clearBtn) {
    clearBtn.addEventListener('click', () => {
      const input = document.getElementById('url-input');
      if (input) input.value = '';
      const resSection = document.getElementById('url-result-section');
      if (resSection) resSection.style.display = 'none';
      const banner = document.getElementById('url-dev-mode-banner');
      if (banner) banner.style.display = 'none';
    });
  }

  // Check URL query param (e.g. ?url=...)
  const urlParams = new URLSearchParams(window.location.search);
  const initialUrl = urlParams.get('url');
  if (initialUrl) {
    const input = document.getElementById('url-input');
    if (input) {
      input.value = initialUrl;
      setTimeout(() => {
        form.dispatchEvent(new Event('submit'));
      }, 100);
    }
  }

  let isAnalyzingUrl = false;
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    if (isAnalyzingUrl) return;

    const input = document.getElementById('url-input');
    const url = input.value.trim();
    if (!url) {
      showToast('Please enter a URL to inspect.', 'warning');
      return;
    }

    isAnalyzingUrl = true;
    const submitBtn = form.querySelector('button[type="submit"]');
    const originalText = submitBtn.innerHTML;
    submitBtn.innerHTML = 'Analyzing...';
    submitBtn.disabled = true;

    const explainChecked = document.getElementById('chk-llm') ? document.getElementById('chk-llm').checked : false;

    try {
      const res = await fetch('/api/analyze-url', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: url, explain: explainChecked })
      });

      const json = await res.json();
      if (!json.success) {
        showToast(json.error || 'Analysis failed.', 'error');
        return;
      }

      renderUrlResults(json.data);
      showToast('URL Analysis complete.', 'success');

    } catch (err) {
      showToast('Server communication error: ' + err, 'error');
    } finally {
      submitBtn.innerHTML = originalText;
      submitBtn.disabled = false;
      isAnalyzingUrl = false;
    }
  });
}

function renderUrlResults(data) {
  if (!data) return;

  const container = document.getElementById('url-result-section');
  if (container) {
    container.style.display = 'block';
    container.scrollIntoView({ behavior: 'smooth' });
  }

  // Dev Mode Banner
  const devBanner = document.getElementById('url-dev-mode-banner');
  if (devBanner) {
    devBanner.style.display = data.model_loaded ? 'none' : 'block';
  }

  // 1. Gauge & Verdict
  const riskCircle = document.getElementById('res-risk-circle');
  const riskScore = document.getElementById('res-risk-score');
  const riskLevel = document.getElementById('res-risk-level');
  if (riskCircle && riskScore && riskLevel) {
    updateRiskGauge(
      riskCircle,
      riskScore,
      riskLevel,
      data.risk_score,
      data.risk_level
    );
  }

  const verdictBadge = document.getElementById('res-verdict-badge');
  if (verdictBadge) {
    if (!data.model_loaded) {
      verdictBadge.className = 'verdict-badge Suspicious';
      verdictBadge.textContent = 'DEV MODE: RULES';
    } else {
      const pred = data.prediction || 'Legitimate';
      verdictBadge.className = 'verdict-badge ' + pred;
      verdictBadge.textContent = pred.toUpperCase();
    }
  }

  const analyzedUrlEl = document.getElementById('res-analyzed-url');
  if (analyzedUrlEl) {
    analyzedUrlEl.textContent = data.normalized_url || data.input_url || '';
  }
  
  const confEl = document.getElementById('res-confidence');
  if (confEl) {
    if (data.confidence !== null && data.confidence !== undefined) {
      confEl.textContent = (data.confidence * 100).toFixed(1) + '%';
    } else {
      confEl.textContent = '-- (Offline / Heuristic)';
    }
  }

  const recEl = document.getElementById('res-recommendation');
  if (recEl) {
    recEl.textContent = data.recommendation || '';
  }

  // 2. Triggered Rules
  const rulesList = document.getElementById('res-rules-list');
  if (rulesList) {
    rulesList.innerHTML = '';
    if (data.triggered_rules && data.triggered_rules.length > 0) {
      data.triggered_rules.forEach(rule => {
        const div = document.createElement('div');
        div.className = `indicator-item ${rule.severity}`;
        div.innerHTML = `
          <div style="flex: 1">
            <div class="indicator-meta ${rule.severity}">${rule.severity} Severity &bull; +${rule.score_impact} pts</div>
            <div class="indicator-name">${escapeHtml(rule.name)}</div>
            <div class="indicator-desc">${escapeHtml(rule.description)}</div>
          </div>
        `;
        rulesList.appendChild(div);
      });
    } else {
      rulesList.innerHTML = '<div style="color: var(--text-muted); font-size: 13px;">No heuristic risk indicators triggered.</div>';
    }
  }

  // 3. Explainability Formula
  const breakdown = data.calculation_breakdown || {};
  const formulaEl = document.getElementById('res-formula');
  if (formulaEl) {
    formulaEl.textContent = breakdown.formula || 'Composite Score Calculated';
  }

  const reasonsList = document.getElementById('res-reasons-list');
  if (reasonsList) {
    reasonsList.innerHTML = '';
    if (data.reasons && data.reasons.length > 0) {
      data.reasons.forEach(r => {
        const li = document.createElement('li');
        li.textContent = r;
        li.style.marginBottom = '6px';
        reasonsList.appendChild(li);
      });
    }
  }

  // 4. LLM Explanation Box
  const llmBox = document.getElementById('res-llm-container');
  if (llmBox) {
    if (data.llm_explanation) {
      llmBox.style.display = 'block';
      const llmText = document.getElementById('res-llm-text');
      if (llmText) llmText.textContent = data.llm_explanation;
    } else {
      llmBox.style.display = 'none';
    }
  }

  // 5. Complete 25 Feature Matrix
  const featGrid = document.getElementById('res-features-grid');
  if (featGrid && data.features) {
    featGrid.innerHTML = '';
    Object.entries(data.features).forEach(([name, val]) => {
      const pill = document.createElement('div');
      pill.className = 'feature-pill';
      pill.innerHTML = `
        <span class="feature-name">${escapeHtml(name)}</span>
        <span class="feature-val">${escapeHtml(String(val))}</span>
      `;
      featGrid.appendChild(pill);
    });
  }

  // Phase 9: Render structured explanation sections
  if (data.explanation && data.explanation.scan_type === 'url') {
    renderP9UrlExplanation(data.explanation);
  }

  // Phase 11: Render threat intelligence section
  renderThreatIntelligence(data.threat_intelligence, 'p11');
}

// ==========================================
// 2. MESSAGE ANALYZER
// ==========================================
function setupMessageAnalyzer() {
  const form = document.getElementById('message-form');
  if (!form) return;

  document.querySelectorAll('.msg-demo-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const input = document.getElementById('message-input');
      input.value = btn.getAttribute('data-msg');
      form.dispatchEvent(new Event('submit'));
    });
  });

  // Clear button
  const clearBtn = document.getElementById('msg-clear-btn');
  if (clearBtn) {
    clearBtn.addEventListener('click', () => {
      const input = document.getElementById('message-input');
      if (input) input.value = '';
      const resSection = document.getElementById('message-result-section');
      if (resSection) resSection.style.display = 'none';
      const banner = document.getElementById('msg-dev-mode-banner');
      if (banner) banner.style.display = 'none';
    });
  }

  let isAnalyzingMsg = false;
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    if (isAnalyzingMsg) return;

    const text = document.getElementById('message-input').value.trim();
    if (!text) {
      showToast('Please enter message text.', 'warning');
      return;
    }

    isAnalyzingMsg = true;
    const submitBtn = form.querySelector('button[type="submit"]');
    const originalText = submitBtn.innerHTML;
    submitBtn.innerHTML = 'Analyzing...';
    submitBtn.disabled = true;

    const explainChecked = document.getElementById('chk-msg-llm') ? document.getElementById('chk-msg-llm').checked : false;

    try {
      const res = await fetch('/api/analyze-message', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ message: text, analyze_urls: true, explain: explainChecked })
      });

      const json = await res.json();
      if (!json.success) {
        showToast(json.error || 'Analysis failed.', 'error');
        return;
      }

      renderMessageResults(json.data);
      showToast('Message analysis completed.', 'success');

    } catch (err) {
      showToast('Server communication error: ' + err, 'error');
    } finally {
      submitBtn.innerHTML = originalText;
      submitBtn.disabled = false;
      isAnalyzingMsg = false;
    }
  });
}

function renderMessageResults(data) {
  const container = document.getElementById('message-result-section');
  if (!container) return;
  container.style.display = 'block';
  container.scrollIntoView({ behavior: 'smooth' });

  // Dev Mode Banner
  const devBanner = document.getElementById('msg-dev-mode-banner');
  if (devBanner) {
    devBanner.style.display = data.model_loaded ? 'none' : 'block';
  }

  updateRiskGauge(
    document.getElementById('msg-risk-circle'),
    document.getElementById('msg-risk-score'),
    document.getElementById('msg-risk-level'),
    data.risk_score,
    data.risk_level
  );

  const verdictBadge = document.getElementById('msg-verdict-badge');
  if (verdictBadge) {
    if (!data.model_loaded) {
      verdictBadge.className = 'verdict-badge Suspicious';
      verdictBadge.textContent = 'DEV MODE: INDICATORS';
    } else {
      verdictBadge.className = 'verdict-badge ' + data.prediction;
      verdictBadge.textContent = data.prediction.toUpperCase();
    }
  }

  document.getElementById('msg-recommendation').textContent = data.recommendation;

  // Model name and probability telemetry
  const modelNameEl = document.getElementById('msg-model-name');
  if (modelNameEl) {
    modelNameEl.textContent = (data.model_info && data.model_info.name) || (data.model_loaded ? 'TF-IDF + Logistic Regression' : 'Heuristic Rule Engine');
  }

  const mlProbEl = document.getElementById('msg-ml-prob');
  if (mlProbEl) {
    const prob = data.ml_probability !== undefined && data.ml_probability !== null ? data.ml_probability : data.confidence;
    if (prob !== null && prob !== undefined) {
      mlProbEl.textContent = (prob * 100).toFixed(1) + '%';
    } else {
      mlProbEl.textContent = '-- (Offline)';
    }
  }

  const mlPredEl = document.getElementById('msg-ml-pred');
  if (mlPredEl) {
    const pred = data.text_ml_prediction || data.nlp_prediction || '--';
    mlPredEl.textContent = pred;
    mlPredEl.style.color = pred.includes('Malicious') || pred.includes('Spam') || pred.includes('Phishing') ? 'var(--coral)' : 'var(--teal)';
  }

  // Text Evidence Vocabulary Chips
  const evList = document.getElementById('msg-text-evidence-list');
  if (evList) {
    evList.innerHTML = '';
    if (data.text_evidence && data.text_evidence.length > 0) {
      data.text_evidence.forEach(item => {
        const chip = document.createElement('div');
        chip.className = 'feature-pill';
        chip.style.display = 'inline-flex';
        chip.style.alignItems = 'center';
        chip.style.gap = '8px';
        chip.innerHTML = `
          <span style="color: var(--teal); font-family: var(--font-mono); font-weight: 700;">${item.term}</span>
          <span style="color: var(--aqua); font-size: 11px; background: rgba(144,174,173,0.2); padding: 1px 6px; border-radius: 4px; font-weight: 600;">+${item.weight}</span>
        `;
        evList.appendChild(chip);
      });
    } else {
      evList.innerHTML = '<span style="color: var(--text-muted); font-size: 13px;">No explicit high-weight adversarial vocabulary detected.</span>';
    }
  }

  // Explainability Formula & Breakdown
  const bd = data.calculation_breakdown || {};
  const formulaEl = document.getElementById('msg-formula');
  if (formulaEl) {
    formulaEl.textContent = bd.formula || 'Composite Score Calculated';
  }

  const bdTextPts = document.getElementById('msg-bd-text-pts');
  if (bdTextPts) {
    bdTextPts.textContent = (bd.text_ml_points !== undefined ? bd.text_ml_points : '--') + ' / 55';
  }

  const bdRulePts = document.getElementById('msg-bd-rule-pts');
  if (bdRulePts) {
    bdRulePts.textContent = (bd.indicator_points_applied !== undefined ? bd.indicator_points_applied : (bd.pattern_points_applied || '--')) + ' / 25';
  }

  const bdUrlPts = document.getElementById('msg-bd-url-pts');
  if (bdUrlPts) {
    bdUrlPts.textContent = (bd.url_points_applied !== undefined ? bd.url_points_applied : (bd.cascaded_url_risk || '0')) + ' / 20';
  }

  // Extracted URLs Section with Direct Link to Mode A URL Analyzer
  const urlSection = document.getElementById('msg-extracted-urls-list');
  urlSection.innerHTML = '';
  if (data.extracted_urls && data.extracted_urls.length > 0) {
    data.extracted_urls.forEach(u => {
      const d = document.createElement('div');
      d.className = 'feature-pill';
      d.style.display = 'flex';
      d.style.justifyContent = 'space-between';
      d.style.alignItems = 'center';
      d.style.flexWrap = 'wrap';
      d.style.gap = '10px';
      d.style.marginBottom = '8px';
      d.innerHTML = `
        <span style="color: var(--teal); font-family: var(--font-mono); word-break: break-all; flex: 1; font-size: 13px;">${u}</span>
        <a href="/url-analyzer?url=${encodeURIComponent(u)}" class="btn-cyber-outline" style="font-size: 11px; padding: 4px 10px; text-decoration: none; display: inline-flex; align-items: center; gap: 4px; white-space: nowrap;">
          Analyze URL →
        </a>
      `;
      urlSection.appendChild(d);
    });
  } else {
    urlSection.innerHTML = '<span style="color: var(--text-muted); font-size: 13px;">No embedded links found in text.</span>';
  }

  // Cascaded URL Findings
  const cascadeContainer = document.getElementById('msg-cascade-section');
  if (cascadeContainer) {
    if (data.url_analyses && data.url_analyses.length > 0) {
      cascadeContainer.style.display = 'block';
      const cList = document.getElementById('msg-cascade-list');
      cList.innerHTML = '';
      data.url_analyses.forEach(ana => {
        const item = document.createElement('div');
        item.className = 'indicator-item ' + (ana.risk_level === 'Critical' ? 'high' : 'medium');
        item.innerHTML = `
          <div>
            <div class="indicator-meta high">Extracted Link Target: ${ana.prediction} (Risk ${ana.risk_score}/100)</div>
            <div class="indicator-name">${ana.normalized_url}</div>
            <div class="indicator-desc">${ana.recommendation}</div>
          </div>
        `;
        cList.appendChild(item);
      });
    } else {
      cascadeContainer.style.display = 'none';
    }
  }

  // NLP Indicators
  const indList = document.getElementById('msg-indicators-list');
  indList.innerHTML = '';
  if (data.detected_indicators && data.detected_indicators.length > 0) {
    data.detected_indicators.forEach(ind => {
      const item = document.createElement('div');
      item.className = `indicator-item ${ind.severity}`;
      item.innerHTML = `
        <div style="flex: 1">
          <div class="indicator-meta ${ind.severity}">${ind.severity} Risk Indicator &bull; ${ind.match_count} Match(es)</div>
          <div class="indicator-name">${ind.name}</div>
          <div class="indicator-desc">${ind.description}</div>
        </div>
      `;
      indList.appendChild(item);
    });
  } else {
    indList.innerHTML = '<div style="color: var(--text-muted); font-size: 13px;">No explicit social engineering patterns detected.</div>';
  }

  // LLM Box
  const llmBox = document.getElementById('msg-llm-container');
  if (llmBox) {
    if (data.llm_explanation) {
      llmBox.style.display = 'block';
      document.getElementById('msg-llm-text').textContent = data.llm_explanation;
    } else {
      llmBox.style.display = 'none';
    }
  }

  // Phase 9: Render structured explanation sections
  if (data.explanation && data.explanation.scan_type === 'message') {
    renderP9MessageExplanation(data.explanation);
  }

  // Phase 11: Render threat intelligence section
  renderThreatIntelligence(data.threat_intelligence, 'msg-p11');
}

// ==========================================
// 3. QR SCANNER
// ==========================================
function setupQrScanner() {
  const dropzone = document.getElementById('qr-dropzone');
  const fileInput = document.getElementById('qr-file-input');
  if (!dropzone || !fileInput) return;

  dropzone.addEventListener('click', () => fileInput.click());

  dropzone.addEventListener('dragover', (e) => {
    e.preventDefault();
    dropzone.classList.add('dragover');
  });

  dropzone.addEventListener('dragleave', () => dropzone.classList.remove('dragover'));

  dropzone.addEventListener('drop', (e) => {
    e.preventDefault();
    dropzone.classList.remove('dragover');
    if (e.dataTransfer.files.length > 0) {
      fileInput.files = e.dataTransfer.files;
      handleQrUpload(e.dataTransfer.files[0]);
    }
  });

  fileInput.addEventListener('change', () => {
    if (fileInput.files.length > 0) {
      handleQrUpload(fileInput.files[0]);
    }
  });
}

async function handleQrUpload(file) {
  const formData = new FormData();
  formData.append('image', file);

  const statusEl = document.getElementById('qr-status');
  if (statusEl) {
    statusEl.textContent = 'Decoding QR code…';
    statusEl.style.color = 'var(--teal)';
  }

  try {
    const res = await fetch('/api/analyze-qr', {
      method: 'POST',
      body: formData
    });
    const json = await res.json();

    if (!json.success) {
      if (statusEl) {
        statusEl.textContent = json.error || 'Failed to decode QR code.';
        statusEl.style.color = 'var(--coral)';
      }
      showToast(json.error || 'QR decode failed.', 'error');
      return;
    }

    const data = json.data;
    if (statusEl) {
      statusEl.textContent = data.qr_detected
        ? '✓ QR Code Decoded Successfully'
        : '✗ No QR code detected.';
      statusEl.style.color = data.qr_detected ? 'var(--teal)' : 'var(--coral)';
    }

    const resultSection = document.getElementById('qr-result-section');
    if (resultSection) {
      resultSection.style.display = 'block';
      resultSection.scrollIntoView({ behavior: 'smooth' });
    }

    // Payload display
    const payloadEl = document.getElementById('qr-extracted-payload');
    if (payloadEl) {
      payloadEl.textContent = data.decoded_payload || data.decoded_text || '(no payload)';
    }

    // Payload type badge
    const badge = document.getElementById('qr-payload-type-badge');
    if (badge) {
      const payloadType = (data.payload_type || 'text').toUpperCase();
      badge.textContent = payloadType;
      badge.style.borderColor = payloadType === 'URL' ? 'var(--teal)' : (payloadType === 'DANGEROUS_SCHEME' ? 'var(--coral)' : 'var(--aqua)');
      badge.style.color = payloadType === 'URL' ? 'var(--teal)' : (payloadType === 'DANGEROUS_SCHEME' ? 'var(--coral)' : 'var(--aqua)');
    }

    if (data.payload_type === 'url' && data.url_analysis) {
      const qrUrlCard = document.getElementById('qr-url-card');
      if (qrUrlCard) qrUrlCard.style.display = 'block';
      const nonUrlCard = document.getElementById('qr-non-url-card');
      if (nonUrlCard) nonUrlCard.style.display = 'none';

      // Set analyzed URL
      const analyzedUrl = document.getElementById('res-analyzed-url');
      if (analyzedUrl) analyzedUrl.textContent = data.decoded_url || '';

      // Render using the existing URL result renderer
      renderUrlResults(data.url_analysis);

      // Phase 9 explanation blocks
      if (data.explanation && data.explanation.scan_type === 'url') {
        renderP9UrlExplanation(data.explanation);
      }

      // Phase 11 Threat Intelligence
      if (typeof renderThreatIntelligence === 'function') {
        const ti = (data.url_analysis && data.url_analysis.threat_intelligence)
                   || data.threat_intelligence
                   || null;
        renderThreatIntelligence(ti, 'qr-p11');
      }
    } else {
      const qrUrlCard = document.getElementById('qr-url-card');
      if (qrUrlCard) qrUrlCard.style.display = 'none';
      const nonUrlCard = document.getElementById('qr-non-url-card');
      if (nonUrlCard) nonUrlCard.style.display = 'block';
      const nonUrlReason = document.getElementById('qr-non-url-reason');
      if (nonUrlReason) nonUrlReason.textContent = data.recommendation || 'Payload is not a web URL — no risk analysis performed.';
      showToast(data.recommendation || 'QR decoded, but payload is not a URL.', 'info');
    }

  } catch (err) {
    if (statusEl) {
      statusEl.textContent = 'Network communication error: ' + err;
      statusEl.style.color = 'var(--coral)';
    }
  }
}

// ==========================================
// 4. SCREENSHOT ANALYZER
// ==========================================
function setupScreenshotAnalyzer() {
  const dropzone = document.getElementById('shot-dropzone');
  const fileInput = document.getElementById('shot-file-input');
  if (!dropzone || !fileInput) return;

  dropzone.addEventListener('click', () => fileInput.click());

  dropzone.addEventListener('dragover', (e) => {
    e.preventDefault();
    dropzone.classList.add('dragover');
  });

  dropzone.addEventListener('dragleave', () => dropzone.classList.remove('dragover'));

  dropzone.addEventListener('drop', (e) => {
    e.preventDefault();
    dropzone.classList.remove('dragover');
    if (e.dataTransfer.files.length > 0) {
      fileInput.files = e.dataTransfer.files;
      handleScreenshotUpload(e.dataTransfer.files[0]);
    }
  });

  fileInput.addEventListener('change', () => {
    if (fileInput.files.length > 0) {
      handleScreenshotUpload(fileInput.files[0]);
    }
  });
}

async function handleScreenshotUpload(file) {
  const formData = new FormData();
  formData.append('image', file);

  const statusEl = document.getElementById('shot-status');
  statusEl.textContent = 'Analyzing screenshot with AI Vision Model...';
  statusEl.style.color = 'var(--accent-cyan)';

  try {
    const res = await fetch('/api/analyze-screenshot', {
      method: 'POST',
      body: formData
    });
    const json = await res.json();

    if (!json.success) {
      statusEl.textContent = json.message || json.error || 'Vision analysis unavailable.';
      statusEl.style.color = 'var(--accent-yellow)';
      showToast(json.message || json.error, 'warning');
      return;
    }

    statusEl.textContent = 'Visual Inspection Complete!';
    statusEl.style.color = 'var(--accent-green)';

    const resultSection = document.getElementById('shot-result-section');
    resultSection.style.display = 'block';
    resultSection.scrollIntoView({ behavior: 'smooth' });

    const d = json.data || {};
    document.getElementById('shot-provider').textContent = json.provider || 'AI Vision';
    document.getElementById('shot-prediction').textContent = d.prediction || 'Unknown';
    document.getElementById('shot-brand').textContent = d.brand_detected || 'None detected';
    document.getElementById('shot-explanation').textContent = d.explanation || 'No summary generated.';
    document.getElementById('shot-recommendation').textContent = d.recommendation || '';

    const indList = document.getElementById('shot-indicators-list');
    indList.innerHTML = '';
    if (d.visual_indicators && d.visual_indicators.length > 0) {
      d.visual_indicators.forEach(item => {
        const li = document.createElement('li');
        li.textContent = item;
        li.style.marginBottom = '6px';
        indList.appendChild(li);
      });
    }

  } catch (err) {
    statusEl.textContent = 'Analysis failed: ' + err;
    statusEl.style.color = 'var(--accent-red)';
  }
}

// Document Init
document.addEventListener('DOMContentLoaded', () => {
  setupUrlAnalyzer();
  setupMessageAnalyzer();
  setupQrScanner();
  setupScreenshotAnalyzer();
});

// ==========================================
// PHASE 9: EXPLANATION RENDERING
// ==========================================

/**
 * Render the Phase 9 structured explanation sections for URL analysis.
 * All data comes from the backend explanation object — no recalculation.
 */
function renderP9UrlExplanation(exp) {
  if (!exp) return;

  // ── WHY WAS THIS FLAGGED? ──
  const whyDiv = document.getElementById('p9-why-flagged');
  const whyList = document.getElementById('p9-why-list');
  if (whyDiv && whyList) {
    whyList.innerHTML = '';
    let idx = 1;

    // Rule evidence items
    const ruleEvidence = exp.rule_evidence || [];
    ruleEvidence.forEach(r => {
      const item = document.createElement('div');
      item.style.cssText = 'display:flex; gap:16px; align-items:flex-start; margin-bottom:14px; padding-bottom:14px; border-bottom:1px solid var(--border-color);';
      item.innerHTML = `
        <div style="min-width:32px; height:32px; background:var(--coral); color:var(--cream); display:flex; align-items:center; justify-content:center; font-weight:900; font-family:var(--font-display); font-size:13px; flex-shrink:0;">${String(idx).padStart(2,'0')}</div>
        <div style="flex:1;">
          <div style="font-weight:700; color:var(--teal); margin-bottom:3px; font-size:14px;">${escapeHtml(r.rule)}</div>
          <div style="font-size:12px; color:var(--text-secondary); line-height:1.6;">${escapeHtml(r.description)}</div>
          <div style="font-size:11px; color:var(--terracotta); margin-top:3px; font-weight:600; text-transform:uppercase; letter-spacing:0.5px;">${r.severity} severity · +${r.contribution} pts</div>
        </div>`;
      whyList.appendChild(item);
      idx++;
    });

    // Suspicious / noteworthy features
    const featureEvidence = (exp.feature_evidence || []).filter(f => f.level === 'suspicious' || f.level === 'noteworthy').slice(0, 5);
    featureEvidence.forEach(f => {
      const item = document.createElement('div');
      item.style.cssText = 'display:flex; gap:16px; align-items:flex-start; margin-bottom:14px; padding-bottom:14px; border-bottom:1px solid var(--border-color);';
      const dotColor = f.level === 'suspicious' ? 'var(--coral)' : 'var(--aqua)';
      item.innerHTML = `
        <div style="min-width:32px; height:32px; background:${dotColor}; color:var(--cream); display:flex; align-items:center; justify-content:center; font-weight:900; font-family:var(--font-display); font-size:13px; flex-shrink:0;">${String(idx).padStart(2,'0')}</div>
        <div style="flex:1;">
          <div style="font-weight:700; color:var(--teal); margin-bottom:3px; font-size:14px;">${escapeHtml(f.name)}</div>
          <div style="font-size:12px; color:var(--text-secondary); line-height:1.6;">${escapeHtml(f.sentence)}</div>
          <div style="font-size:11px; color:${dotColor}; margin-top:3px; font-weight:600; text-transform:uppercase; letter-spacing:0.5px;">Observation: ${f.level}</div>
        </div>`;
      whyList.appendChild(item);
      idx++;
    });

    // ML probability item if elevated
    const mlEv = exp.ml_evidence || {};
    if (mlEv.phishing_probability_pct >= 50) {
      const mlItem = document.createElement('div');
      mlItem.style.cssText = 'display:flex; gap:16px; align-items:flex-start; margin-bottom:14px;';
      mlItem.innerHTML = `
        <div style="min-width:32px; height:32px; background:var(--terracotta); color:var(--cream); display:flex; align-items:center; justify-content:center; font-weight:900; font-family:var(--font-display); font-size:13px; flex-shrink:0;">${String(idx).padStart(2,'0')}</div>
        <div style="flex:1;">
          <div style="font-weight:700; color:var(--teal); margin-bottom:3px; font-size:14px;">Elevated Model Probability</div>
          <div style="font-size:12px; color:var(--text-secondary); line-height:1.6;">${escapeHtml(mlEv.interpretation || '')}</div>
          <div style="font-size:11px; color:var(--terracotta); margin-top:3px; font-weight:600; text-transform:uppercase; letter-spacing:0.5px;">Random Forest · ${mlEv.phishing_probability_pct}% phishing probability</div>
        </div>`;
      whyList.appendChild(mlItem);
    }

    if (idx === 1) {
      whyList.innerHTML = '<div style="color:var(--text-muted); font-size:13px;">No significant risk indicators were flagged for this URL.</div>';
    }
    whyDiv.style.display = 'block';
  }

  // ── WHAT DOES THIS MEAN? ──
  const whatDiv = document.getElementById('p9-what-means');
  const whatText = document.getElementById('p9-what-text');
  if (whatDiv && whatText && exp.what_does_this_mean) {
    whatText.textContent = exp.what_does_this_mean;
    whatDiv.style.display = 'block';
  }

  // ── RISK CONTRIBUTION ──
  const riskDiv = document.getElementById('p9-risk-contrib');
  if (riskDiv && exp.risk_contribution) {
    const rc = exp.risk_contribution;
    const mlEl = document.getElementById('p9-ml-pts');
    const ruleEl = document.getElementById('p9-rule-pts');
    const totalEl = document.getElementById('p9-total-score');
    const formulaEl = document.getElementById('p9-formula-text');
    if (mlEl) mlEl.textContent = `${rc.ml_points} / ${rc.ml_points_maximum}`;
    if (ruleEl) ruleEl.textContent = `${rc.rule_points} / ${rc.rule_points_maximum}`;
    if (totalEl) totalEl.textContent = `${rc.total_score} / ${rc.total_maximum}`;
    if (formulaEl) formulaEl.textContent = rc.formula || '';
    riskDiv.style.display = 'block';
  }

  // ── INVESTIGATION TIMELINE ──
  const tlDiv = document.getElementById('p9-timeline');
  const tlList = document.getElementById('p9-timeline-list');
  if (tlDiv && tlList && exp.investigation_stages) {
    tlList.innerHTML = '';
    exp.investigation_stages.forEach((stage, i) => {
      const isLast = i === exp.investigation_stages.length - 1;
      const stageDiv = document.createElement('div');
      stageDiv.style.cssText = 'display:flex; gap:16px; align-items:flex-start;' + (isLast ? '' : ' margin-bottom:4px;');
      stageDiv.innerHTML = `
        <div style="display:flex; flex-direction:column; align-items:center; flex-shrink:0;">
          <div style="width:12px; height:12px; background:var(--teal); border-radius:50%; border:2px solid var(--aqua); flex-shrink:0; margin-top:4px;"></div>
          ${!isLast ? '<div style="width:2px; flex:1; background:var(--border-color); min-height:28px; margin-top:2px;"></div>' : ''}
        </div>
        <div style="padding-bottom:${isLast ? 0 : 16}px; flex:1;">
          <div style="font-weight:700; font-size:13px; color:var(--teal); font-family:var(--font-display);">${escapeHtml(stage.stage)}</div>
          <div style="font-size:12px; color:var(--text-secondary); margin-top:2px;">${escapeHtml(stage.detail)}</div>
        </div>`;
      tlList.appendChild(stageDiv);
    });
    tlDiv.style.display = 'block';
  }

  // ── TECHNICAL FEATURE INSPECTOR ──
  const inspDiv = document.getElementById('p9-feature-inspector');
  const inspTable = document.getElementById('p9-inspector-table');
  if (inspDiv && inspTable && exp.feature_evidence) {
    inspTable.innerHTML = '';
    const table = document.createElement('table');
    table.style.cssText = 'width:100%; border-collapse:collapse; font-size:12px;';
    table.innerHTML = `<thead><tr style="background:var(--teal); color:var(--cream);">
      <th style="padding:8px 12px; text-align:left; font-family:var(--font-display); text-transform:uppercase; letter-spacing:1px; font-weight:700; font-size:11px;">Feature</th>
      <th style="padding:8px 12px; text-align:center; font-family:var(--font-display); text-transform:uppercase; letter-spacing:1px; font-weight:700; font-size:11px;">Value</th>
      <th style="padding:8px 12px; text-align:left; font-family:var(--font-display); text-transform:uppercase; letter-spacing:1px; font-weight:700; font-size:11px;">Observation</th>
      <th style="padding:8px 12px; text-align:center; font-family:var(--font-display); text-transform:uppercase; letter-spacing:1px; font-weight:700; font-size:11px;">Level</th>
    </tr></thead>`;
    const tbody = document.createElement('tbody');
    exp.feature_evidence.forEach((f, i) => {
      const levelColor = f.level === 'suspicious' ? 'var(--coral)' : (f.level === 'noteworthy' ? 'var(--terracotta)' : 'var(--aqua)');
      const tr = document.createElement('tr');
      tr.style.cssText = `background: ${i % 2 === 0 ? 'var(--cream)' : 'var(--cream-light)'}; border-bottom:1px solid var(--border-color);`;
      tr.innerHTML = `
        <td style="padding:8px 12px; font-family:var(--font-mono); font-size:11px; color:var(--teal); font-weight:600;">${escapeHtml(f.name)}</td>
        <td style="padding:8px 12px; text-align:center; font-family:var(--font-mono); font-weight:700; color:var(--teal);">${f.value}</td>
        <td style="padding:8px 12px; color:var(--text-secondary); font-size:11px; line-height:1.5;">${escapeHtml(f.sentence)}</td>
        <td style="padding:8px 12px; text-align:center;">
          <span style="font-size:10px; font-weight:700; text-transform:uppercase; letter-spacing:0.5px; color:${levelColor}; background:rgba(0,0,0,0.04); padding:2px 6px; border:1px solid ${levelColor};">${f.level}</span>
        </td>`;
      tbody.appendChild(tr);
    });
    table.appendChild(tbody);
    inspTable.appendChild(table);
    inspDiv.style.display = 'block';
  }

  // ── GLOBAL MODEL FEATURE IMPORTANCE ──
  const gfiDiv = document.getElementById('p9-global-importance');
  const gfiList = document.getElementById('p9-importance-list');
  if (gfiDiv && gfiList && exp.global_feature_importance) {
    const gfi = exp.global_feature_importance;
    gfiList.innerHTML = '';
    const maxImp = gfi.top_features.length > 0 ? gfi.top_features[0].importance : 1;
    gfi.top_features.forEach((f, i) => {
      const pct = maxImp > 0 ? (f.importance / maxImp * 100).toFixed(0) : 0;
      const row = document.createElement('div');
      row.style.cssText = 'margin-bottom:10px;';
      row.innerHTML = `
        <div style="display:flex; justify-content:space-between; margin-bottom:3px;">
          <span style="font-family:var(--font-mono); font-size:12px; font-weight:600; color:var(--teal);">${i+1}. ${escapeHtml(f.feature)}</span>
          <span style="font-size:12px; font-weight:700; color:var(--terracotta); font-family:var(--font-display);">${f.importance.toFixed(5)}</span>
        </div>
        <div style="background:var(--cream-dark); height:6px; border-radius:0;">
          <div style="height:100%; width:${pct}%; background:var(--terracotta);"></div>
        </div>`;
      gfiList.appendChild(row);
    });
    gfiDiv.style.display = 'block';
  } else if (gfiDiv) {
    gfiDiv.style.display = 'none';
  }
}

/**
 * Render the Phase 9 structured explanation sections for message analysis.
 */
function renderP9MessageExplanation(exp) {
  if (!exp) return;

  // ── WHY WAS THIS FLAGGED? ──
  const whyDiv = document.getElementById('msg-p9-why-flagged');
  const whyList = document.getElementById('msg-p9-why-list');
  if (whyDiv && whyList) {
    whyList.innerHTML = '';
    let idx = 1;

    (exp.indicator_evidence || []).forEach(ind => {
      const item = document.createElement('div');
      item.style.cssText = 'display:flex; gap:16px; align-items:flex-start; margin-bottom:14px; padding-bottom:14px; border-bottom:1px solid var(--border-color);';
      const sevColor = ind.severity === 'critical' ? 'var(--coral)' : (ind.severity === 'high' ? 'var(--terracotta)' : 'var(--aqua)');
      item.innerHTML = `
        <div style="min-width:32px; height:32px; background:${sevColor}; color:var(--cream); display:flex; align-items:center; justify-content:center; font-weight:900; font-family:var(--font-display); font-size:13px; flex-shrink:0;">${String(idx).padStart(2,'0')}</div>
        <div style="flex:1;">
          <div style="font-weight:700; color:var(--teal); margin-bottom:3px; font-size:14px;">${escapeHtml(ind.name)}</div>
          <div style="font-size:12px; color:var(--text-secondary); line-height:1.6;">${escapeHtml(ind.description)}</div>
          <div style="font-size:11px; color:${sevColor}; margin-top:3px; font-weight:600; text-transform:uppercase; letter-spacing:0.5px;">${ind.severity} · ${ind.match_count} match(es) · +${ind.severity_score} pts</div>
        </div>`;
      whyList.appendChild(item);
      idx++;
    });

    const mlEv = exp.ml_evidence || {};
    if (mlEv.malicious_probability_pct !== null && mlEv.malicious_probability_pct >= 50) {
      const mlItem = document.createElement('div');
      mlItem.style.cssText = 'display:flex; gap:16px; align-items:flex-start; margin-bottom:14px;';
      mlItem.innerHTML = `
        <div style="min-width:32px; height:32px; background:var(--terracotta); color:var(--cream); display:flex; align-items:center; justify-content:center; font-weight:900; font-family:var(--font-display); font-size:13px; flex-shrink:0;">${String(idx).padStart(2,'0')}</div>
        <div style="flex:1;">
          <div style="font-weight:700; color:var(--teal); margin-bottom:3px; font-size:14px;">Elevated SMS Malicious-Message Probability</div>
          <div style="font-size:12px; color:var(--text-secondary); line-height:1.6;">${escapeHtml(mlEv.interpretation || '')}</div>
          <div style="font-size:11px; color:var(--terracotta); margin-top:3px; font-weight:600; text-transform:uppercase; letter-spacing:0.5px;">TF-IDF + LR · ${mlEv.malicious_probability_pct}% malicious/spam probability</div>
        </div>`;
      whyList.appendChild(mlItem);
    }

    if (idx === 1) {
      whyList.innerHTML = '<div style="color:var(--text-muted); font-size:13px;">No significant risk indicators were flagged for this message.</div>';
    }
    whyDiv.style.display = 'block';
  }

  // ── WHAT DOES THIS MEAN? ──
  const whatDiv = document.getElementById('msg-p9-what-means');
  const whatText = document.getElementById('msg-p9-what-text');
  if (whatDiv && whatText && exp.what_does_this_mean) {
    whatText.textContent = exp.what_does_this_mean;
    whatDiv.style.display = 'block';
  }

  // ── RISK CONTRIBUTION ──
  const riskDiv = document.getElementById('msg-p9-risk-contrib');
  if (riskDiv && exp.risk_contribution) {
    const rc = exp.risk_contribution;
    const setEl = (id, val) => { const el = document.getElementById(id); if (el) el.textContent = val; };
    setEl('msg-p9-ml-pts', `${rc.text_ml_points} / ${rc.text_ml_points_maximum}`);
    setEl('msg-p9-ind-pts', `${rc.indicator_points} / ${rc.indicator_points_maximum}`);
    setEl('msg-p9-url-pts', `${rc.url_cascade_points} / ${rc.url_cascade_points_maximum}`);
    setEl('msg-p9-total', `${rc.total_score} / ${rc.total_maximum}`);
    riskDiv.style.display = 'block';
  }

  // ── INVESTIGATION TIMELINE ──
  const tlDiv = document.getElementById('msg-p9-timeline');
  const tlList = document.getElementById('msg-p9-timeline-list');
  if (tlDiv && tlList && exp.investigation_stages) {
    tlList.innerHTML = '';
    exp.investigation_stages.forEach((stage, i) => {
      const isLast = i === exp.investigation_stages.length - 1;
      const stageDiv = document.createElement('div');
      stageDiv.style.cssText = 'display:flex; gap:16px; align-items:flex-start;';
      stageDiv.innerHTML = `
        <div style="display:flex; flex-direction:column; align-items:center; flex-shrink:0;">
          <div style="width:12px; height:12px; background:var(--teal); border-radius:50%; border:2px solid var(--aqua); flex-shrink:0; margin-top:4px;"></div>
          ${!isLast ? '<div style="width:2px; flex:1; background:var(--border-color); min-height:28px; margin-top:2px;"></div>' : ''}
        </div>
        <div style="padding-bottom:${isLast ? 0 : 16}px; flex:1;">
          <div style="font-weight:700; font-size:13px; color:var(--teal); font-family:var(--font-display);">${escapeHtml(stage.stage)}</div>
          <div style="font-size:12px; color:var(--text-secondary); margin-top:2px;">${escapeHtml(stage.detail)}</div>
        </div>`;
      tlList.appendChild(stageDiv);
    });
    tlDiv.style.display = 'block';
  }
}

/** Simple HTML escaper to prevent XSS from any explanation strings */
function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/**
 * Render Phase 11 Threat Intelligence evidence into elements matching prefix.
 * Prefixes used: 'p11' (URL, QR) and 'msg-p11' (Message URL cascade).
 */
function renderThreatIntelligence(ti, prefix = 'p11') {
  const container = document.getElementById(`${prefix}-threat-intel`);
  const badge = document.getElementById(`${prefix}-ti-status-badge`);
  const body = document.getElementById(`${prefix}-ti-body`);
  if (!container || !body) return;

  if (!ti || !ti.enabled) {
    if (badge) {
      badge.textContent = 'Not Configured';
      badge.style.background = 'var(--cream-dark)';
      badge.style.color = 'var(--text-muted)';
      badge.style.border = '1px solid var(--border-color)';
    }
    body.innerHTML = `
      <div style="font-size:13px; color:var(--text-secondary); line-height:1.6;">
        <strong>Threat Intelligence:</strong> Not configured on this environment.
        Analysis is operating strictly using local Random Forest inference and deterministic rule indicators.
      </div>`;
    container.style.display = 'block';
    return;
  }

  const sum = ti.summary || {};
  const status = sum.status;
  const detections = sum.detections || 0;
  const total = sum.total_engines || 0;
  const isMalicious = sum.malicious;

  if (status === 'success') {
    if (isMalicious) {
      if (badge) {
        badge.textContent = 'MALICIOUS DETECTIONS';
        badge.style.background = 'var(--coral)';
        badge.style.color = 'var(--cream)';
        badge.style.border = '1px solid var(--coral)';
      }
      body.innerHTML = `
        <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:12px; margin-bottom:12px; border-bottom:1px solid var(--border-color); padding-bottom:10px;">
          <div>
            <div style="font-size:14px; font-weight:800; color:var(--coral); font-family:var(--font-display);">VirusTotal External Intelligence</div>
            <div style="font-size:12px; color:var(--text-secondary); margin-top:2px;">Corroboration from global security & scanning engines.</div>
          </div>
          <div style="text-align:right;">
            <div style="font-size:22px; font-weight:900; color:var(--coral); font-family:var(--font-display); line-height:1;">${detections} / ${total}</div>
            <div style="font-size:11px; text-transform:uppercase; color:var(--text-muted); letter-spacing:0.5px; font-weight:700;">Engines Flagged</div>
          </div>
        </div>
        <div style="font-size:12.5px; color:var(--text-secondary); line-height:1.7;">
          ${escapeHtml(sum.description || '')}
        </div>
        <div style="margin-top:10px; font-size:11px; color:var(--text-muted); background:var(--cream-dark); padding:8px 12px; border-radius:var(--radius-sm);">
          <strong>Academic Note:</strong> Threat intelligence serves as bounded corroborating evidence (+${sum.risk_points || 0} pts applied). Local machine learning and cybersecurity rules remain the primary classification engine.
        </div>`;
    } else {
      if (badge) {
        badge.textContent = 'CLEAN';
        badge.style.background = 'var(--teal)';
        badge.style.color = 'var(--cream)';
        badge.style.border = '1px solid var(--teal)';
      }
      body.innerHTML = `
        <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:12px; margin-bottom:12px; border-bottom:1px solid var(--border-color); padding-bottom:10px;">
          <div>
            <div style="font-size:14px; font-weight:800; color:var(--teal); font-family:var(--font-display);">VirusTotal External Intelligence</div>
            <div style="font-size:12px; color:var(--text-secondary); margin-top:2px;">No malicious detections were reported by the queried provider.</div>
          </div>
          <div style="text-align:right;">
            <div style="font-size:22px; font-weight:900; color:var(--teal); font-family:var(--font-display); line-height:1;">0 / ${total}</div>
            <div style="font-size:11px; text-transform:uppercase; color:var(--text-muted); letter-spacing:0.5px; font-weight:700;">Engines Flagged</div>
          </div>
        </div>
        <div style="font-size:12.5px; color:var(--text-secondary); line-height:1.7;">
          ${escapeHtml(sum.description || '')}
        </div>
        <div style="margin-top:10px; font-size:11px; color:var(--text-muted); background:var(--cream-dark); padding:8px 12px; border-radius:var(--radius-sm);">
          <strong>Academic Note:</strong> Zero external detections does not guarantee 100% safety (zero-day phishing domains may not yet be cataloged). The local ML model and rules evaluated this resource independently.
        </div>`;
    }
  } else {
    // Timeout, rate limited, not found, or error
    if (badge) {
      badge.textContent = (status || 'UNAVAILABLE').toUpperCase();
      badge.style.background = 'var(--terracotta)';
      badge.style.color = 'var(--cream)';
      badge.style.border = '1px solid var(--terracotta)';
    }
    body.innerHTML = `
      <div style="font-size:13px; color:var(--text-secondary); line-height:1.6;">
        <div style="font-weight:700; color:var(--terracotta); margin-bottom:4px;">Threat Intelligence Unavailable</div>
        <div>${escapeHtml(sum.description || 'External intelligence query could not be completed.')}</div>
        <div style="margin-top:8px; font-size:11px; color:var(--text-muted);">
          Local analysis results were preserved with zero risk degradation.
        </div>
      </div>`;
  }

  container.style.display = 'block';
}


