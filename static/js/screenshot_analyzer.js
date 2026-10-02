/**
 * screenshot_analyzer.js - Frontend interactions and rendering for Phase 12 Visual Phishing Detection
 */

function handleShotDrop(event) {
  event.preventDefault();
  event.currentTarget.style.borderColor = 'var(--border-color)';
  event.currentTarget.style.background = 'var(--cream-light)';
  const files = event.dataTransfer.files;
  if (files && files.length > 0) {
    processScreenshotFile(files[0]);
  }
}

function onShotFileSelect(event) {
  const files = event.target.files;
  if (files && files.length > 0) {
    processScreenshotFile(files[0]);
  }
}

function clearShotUpload() {
  const fileInput = document.getElementById('shot-file-input');
  if (fileInput) fileInput.value = '';

  const previewWrap = document.getElementById('shot-preview-wrap');
  const previewImg = document.getElementById('shot-preview-img');
  const clearBtn = document.getElementById('shot-clear-btn');
  const icon = document.getElementById('shot-dropzone-icon');
  const statusEl = document.getElementById('shot-status');
  const resultSec = document.getElementById('shot-result-section');

  if (previewWrap) previewWrap.style.display = 'none';
  if (previewImg) previewImg.src = '';
  if (clearBtn) clearBtn.style.display = 'none';
  if (icon) icon.style.display = 'block';
  if (statusEl) {
    statusEl.textContent = '';
    statusEl.className = '';
  }
  if (resultSec) resultSec.style.display = 'none';
}

async function processScreenshotFile(file) {
  const allowed = ['image/png', 'image/jpeg', 'image/webp', 'image/bmp'];
  if (!allowed.includes(file.type) && !file.name.match(/\.(png|jpe?g|webp|bmp)$/i)) {
    showToast('Unsupported file type. Please upload a PNG, JPG, WEBP, or BMP image.', 'warning');
    return;
  }

  if (file.size > 10 * 1024 * 1024) {
    showToast('File size exceeds the 10 MB maximum limit.', 'error');
    return;
  }

  // Preview thumbnail
  const reader = new FileReader();
  reader.onload = (e) => {
    const previewImg = document.getElementById('shot-preview-img');
    const previewWrap = document.getElementById('shot-preview-wrap');
    const icon = document.getElementById('shot-dropzone-icon');
    const clearBtn = document.getElementById('shot-clear-btn');

    if (previewImg && previewWrap) {
      previewImg.src = e.target.result;
      previewWrap.style.display = 'block';
    }
    if (icon) icon.style.display = 'none';
    if (clearBtn) clearBtn.style.display = 'inline-block';
  };
  reader.readAsDataURL(file);

  const statusEl = document.getElementById('shot-status');
  if (statusEl) {
    statusEl.textContent = 'Processing screenshot in memory: running OpenCV heuristics and OCR extraction...';
    statusEl.style.color = 'var(--teal)';
  }

  const formData = new FormData();
  formData.append('image', file);

  try {
    const res = await fetch('/api/analyze-screenshot', {
      method: 'POST',
      body: formData
    });

    const json = await res.json();

    if (!json.success) {
      if (statusEl) {
        statusEl.textContent = json.error || 'Visual analysis failed.';
        statusEl.style.color = 'var(--coral)';
      }
      showToast(json.error || 'Screenshot analysis failed.', 'error');
      return;
    }

    if (statusEl) {
      statusEl.textContent = 'Screenshot Analyzed Successfully!';
      statusEl.style.color = 'var(--teal)';
    }

    renderScreenshotResults(json.data);
    showToast('Visual analysis completed.', 'success');

  } catch (err) {
    if (statusEl) {
      statusEl.textContent = 'Network or processing error: ' + err;
      statusEl.style.color = 'var(--coral)';
    }
    showToast('Failed to communicate with analysis server.', 'error');
  }
}

function renderScreenshotResults(data) {
  const resultSec = document.getElementById('shot-result-section');
  if (!resultSec) return;
  resultSec.style.display = 'block';
  resultSec.scrollIntoView({ behavior: 'smooth' });

  const score = data.risk_score || 0;
  const level = data.risk_level || 'Low';
  const prediction = (data.prediction || 'Legitimate').toUpperCase();

  // 1. Hero Gauge & Verdict
  const circle = document.getElementById('shot-risk-circle');
  if (circle) circle.className = `risk-circle ${level}`;

  const scoreEl = document.getElementById('shot-risk-score');
  if (scoreEl) scoreEl.textContent = score;

  const lvlEl = document.getElementById('shot-risk-level');
  if (lvlEl) {
    lvlEl.className = `badge-risk-level ${level}`;
    lvlEl.textContent = `${level} Risk`;
  }

  const vBadge = document.getElementById('shot-verdict-badge');
  if (vBadge) {
    vBadge.className = `verdict-badge ${data.prediction || 'Legitimate'}`;
    vBadge.textContent = prediction;
  }

  const predText = document.getElementById('shot-prediction-text');
  if (predText) {
    predText.textContent = `${prediction} (Visual Risk Score: ${score}/100)`;
  }

  const recEl = document.getElementById('shot-recommendation');
  if (recEl) {
    recEl.textContent = data.recommendation || 'Maintain standard security vigilance.';
  }

  // 2. Visual Structure Metrics
  const vis = data.visual_analysis || {};
  const setEl = (id, val) => { const el = document.getElementById(id); if (el) el.textContent = val; };

  setEl('shot-metric-inputs', vis.input_fields !== undefined ? vis.input_fields : 0);
  setEl('shot-metric-buttons', vis.buttons !== undefined ? vis.buttons : 0);
  setEl('shot-metric-contours', vis.contour_count !== undefined ? vis.contour_count : 0);
  setEl('shot-visual-pts-badge', `${vis.visual_points || 0} / 35 pts`);

  const interpEl = document.getElementById('shot-visual-interpretation');
  if (interpEl) {
    const inputs = vis.input_fields || 0;
    const buttons = vis.buttons || 0;
    if (inputs >= 2 && buttons >= 1) {
      interpEl.innerHTML = `<strong>High Structural Risk:</strong> The image contains visual characteristics typical of a login or authentication capture portal (${inputs} inputs, ${buttons} action button).`;
    } else if (inputs >= 1 || buttons >= 1) {
      interpEl.innerHTML = `<strong>Moderate Structural Cues:</strong> Detected ${inputs} input-like region(s) and ${buttons} button(s).`;
    } else {
      interpEl.innerHTML = `<strong>Benign Structure:</strong> Minimal interactive form contours observed (${inputs} inputs, ${buttons} buttons).`;
    }
  }

  // 3. OCR Text Findings
  const ocrAvailable = data.ocr_available;
  const ocrBadge = document.getElementById('shot-ocr-status-badge');
  const ocrPreview = document.getElementById('shot-ocr-preview');
  const ocrUnavail = document.getElementById('shot-ocr-unavailable');
  const indList = document.getElementById('shot-text-indicators-list');

  if (ocrAvailable) {
    if (ocrBadge) {
      ocrBadge.textContent = 'OCR ACTIVE';
      ocrBadge.style.background = 'var(--teal)';
      ocrBadge.style.color = 'var(--cream)';
    }
    if (ocrUnavail) ocrUnavail.style.display = 'none';
    if (ocrPreview) {
      ocrPreview.style.display = 'block';
      ocrPreview.textContent = data.ocr_text || '(No visible alphanumeric text extracted by OCR engine)';
    }

    if (indList) {
      indList.innerHTML = '';
      const inds = vis.indicators || {};
      const categories = Object.keys(inds);
      if (categories.length > 0) {
        let html = '<div style="display:flex; flex-wrap:wrap; gap:8px; margin-bottom:8px;">';
        categories.forEach(cat => {
          const words = inds[cat] || [];
          words.forEach(w => {
            html += `<span style="background:var(--cream-dark); border:1px solid var(--terracotta); color:var(--terracotta); padding:3px 8px; font-size:11px; font-weight:700; border-radius:2px; text-transform:uppercase;">[${cat.toUpperCase()}] ${escapeHtml(w)}</span>`;
          });
        });
        html += '</div>';
        indList.innerHTML = html;
      } else {
        indList.innerHTML = '<div style="font-size:12px; color:var(--text-muted); font-style:italic;">No suspicious credential, urgency, or financial keywords identified in extracted text.</div>';
      }
    }
  } else {
    if (ocrBadge) {
      ocrBadge.textContent = 'OCR OFFLINE';
      ocrBadge.style.background = 'var(--cream-dark)';
      ocrBadge.style.color = 'var(--text-muted)';
      ocrBadge.style.border = '1px solid var(--border-color)';
    }
    if (ocrUnavail) ocrUnavail.style.display = 'block';
    if (ocrPreview) ocrPreview.style.display = 'none';
    if (indList) indList.innerHTML = '';
  }

  // 4. Extracted URLs and Brand Mismatch
  const cascadeCard = document.getElementById('shot-url-cascade-card');
  const urls = data.extracted_urls || [];
  if (urls.length > 0 && cascadeCard) {
    cascadeCard.style.display = 'block';
    const urlsList = document.getElementById('shot-extracted-urls-list');
    if (urlsList) {
      urlsList.innerHTML = urls.map(u =>
        `<div style="font-family:var(--font-mono); font-size:12px; color:var(--teal); background:var(--cream-dark); padding:6px 10px; border-radius:2px; margin-bottom:4px; word-break:break-all;">🔗 ${escapeHtml(u)}</div>`
      ).join('');
    }

    const misBadge = document.getElementById('shot-mismatch-badge');
    const misPts = data.brand_mismatch_points || 0;
    if (misBadge) {
      if (misPts > 0) {
        misBadge.textContent = `BRAND MISMATCH (+${misPts} PTS)`;
        misBadge.style.color = 'var(--coral)';
      } else {
        misBadge.textContent = 'CONSISTENT';
        misBadge.style.color = 'var(--teal)';
      }
    }

    const urlSum = document.getElementById('shot-url-analysis-summary');
    if (urlSum && data.url_analysis) {
      const ua = data.url_analysis;
      urlSum.innerHTML = `
        <div style="font-weight:700; color:var(--teal); margin-bottom:4px;">Cascaded URL Analysis:</div>
        <div>Destination: <strong>${escapeHtml(ua.normalized_url || ua.input_url || '')}</strong></div>
        <div>URL Risk Score: <strong>${ua.risk_score || 0}/100</strong> (${ua.risk_level || 'Low'} Risk) · Verdict: <strong>${escapeHtml(ua.prediction || '')}</strong></div>
      `;
    }
  } else if (cascadeCard) {
    cascadeCard.style.display = 'none';
  }

  // 5. Phase 9 Explainable AI Sections
  const exp = data.explanation || {};

  // WHY WAS THIS FLAGGED
  const whyList = document.getElementById('shot-why-list');
  if (whyList) {
    whyList.innerHTML = '';
    let idx = 1;

    // Visual structure reason
    if (vis.visual_points > 0) {
      const item = document.createElement('div');
      item.style.cssText = 'display:flex; gap:16px; align-items:flex-start; margin-bottom:14px;';
      item.innerHTML = `
        <div style="min-width:32px; height:32px; background:var(--teal); color:var(--cream); display:flex; align-items:center; justify-content:center; font-weight:900; font-family:var(--font-display); font-size:13px; flex-shrink:0;">${String(idx++).padStart(2,'0')}</div>
        <div style="flex:1;">
          <div style="font-weight:700; color:var(--teal); margin-bottom:3px; font-size:14px;">Suspicious Visual Layout Geometry</div>
          <div style="font-size:12px; color:var(--text-secondary); line-height:1.6;">OpenCV analysis identified ${vis.input_fields || 0} form input field(s) and ${vis.buttons || 0} button-like element(s).</div>
          <div style="font-size:11px; color:var(--coral); margin-top:3px; font-weight:600; text-transform:uppercase; letter-spacing:0.5px;">+${vis.visual_points} pts visual contribution</div>
        </div>`;
      whyList.appendChild(item);
    }

    // OCR keywords reason
    const bd = data.calculation_breakdown || {};
    if (bd.text_points > 0) {
      const item = document.createElement('div');
      item.style.cssText = 'display:flex; gap:16px; align-items:flex-start; margin-bottom:14px;';
      item.innerHTML = `
        <div style="min-width:32px; height:32px; background:var(--terracotta); color:var(--cream); display:flex; align-items:center; justify-content:center; font-weight:900; font-family:var(--font-display); font-size:13px; flex-shrink:0;">${String(idx++).padStart(2,'0')}</div>
        <div style="flex:1;">
          <div style="font-weight:700; color:var(--teal); margin-bottom:3px; font-size:14px;">High-Risk Linguistic Phishing Keywords</div>
          <div style="font-size:12px; color:var(--text-secondary); line-height:1.6;">Extracted text matches known credential harvesting, urgency, or banking patterns.</div>
          <div style="font-size:11px; color:var(--coral); margin-top:3px; font-weight:600; text-transform:uppercase; letter-spacing:0.5px;">+${bd.text_points} pts text indicator contribution</div>
        </div>`;
      whyList.appendChild(item);
    }

    // Mismatch reason
    if (bd.mismatch_points > 0) {
      const item = document.createElement('div');
      item.style.cssText = 'display:flex; gap:16px; align-items:flex-start; margin-bottom:14px;';
      item.innerHTML = `
        <div style="min-width:32px; height:32px; background:var(--coral); color:var(--cream); display:flex; align-items:center; justify-content:center; font-weight:900; font-family:var(--font-display); font-size:13px; flex-shrink:0;">${String(idx++).padStart(2,'0')}</div>
        <div style="flex:1;">
          <div style="font-weight:700; color:var(--teal); margin-bottom:3px; font-size:14px;">Brand vs. Domain Inconsistency</div>
          <div style="font-size:12px; color:var(--text-secondary); line-height:1.6;">A recognized target brand name was detected in visual text, but the extracted destination domain does not match legitimate brand properties.</div>
          <div style="font-size:11px; color:var(--coral); margin-top:3px; font-weight:600; text-transform:uppercase; letter-spacing:0.5px;">+${bd.mismatch_points} pts brand mismatch penalty</div>
        </div>`;
      whyList.appendChild(item);
    }

    if (idx === 1) {
      whyList.innerHTML = '<div style="color:var(--text-muted); font-size:13px; padding:10px 0;">No significant visual phishing indicators were flagged for this screenshot.</div>';
    }
  }

  // WHAT DOES THIS MEAN
  const whatText = document.getElementById('shot-what-text');
  if (whatText && exp.what_does_this_mean) {
    whatText.textContent = exp.what_does_this_mean;
  }

  // RISK CONTRIBUTION
  const bd = data.calculation_breakdown || {};
  setEl('shot-cb-vis-pts', `${bd.visual_points || 0} / ${bd.visual_max || 35}`);
  setEl('shot-cb-txt-pts', `${bd.text_points || 0} / ${bd.text_max || 25}`);
  setEl('shot-cb-mis-pts', `${bd.mismatch_points || 0} / ${bd.mismatch_max || 20}`);
  setEl('shot-cb-url-pts', `${bd.url_cascade_points || 0} / ${bd.url_cascade_max || 20}`);
  setEl('shot-cb-total-pts', `${score} / 100`);

  const formulaEl = document.getElementById('shot-formula-text');
  if (formulaEl) {
    formulaEl.textContent = bd.formula || `Final Risk Score = min(100, Visual + Text + Mismatch + URL_Cascade) = ${score}/100`;
  }

  // INVESTIGATION TIMELINE
  const tlList = document.getElementById('shot-timeline-list');
  if (tlList && exp.investigation_stages) {
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
  }

  // 6. Threat Intelligence (if URL present & TI returned)
  const ti = (data.url_analysis && data.url_analysis.threat_intelligence) || data.threat_intelligence;
  const tiContainer = document.getElementById('shot-p11-threat-intel');
  if (ti && tiContainer) {
    if (typeof renderThreatIntelligence === 'function') {
      renderThreatIntelligence(ti, 'shot-p11');
    }
  } else if (tiContainer) {
    tiContainer.style.display = 'none';
  }
}
