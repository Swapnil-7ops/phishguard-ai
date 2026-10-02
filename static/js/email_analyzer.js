/**
 * email_analyzer.js - PhishGuard AI Email (.EML) Phishing Analyzer Frontend
 *
 * Handles file drop, file picking, client validation, FormData submission to
 * /api/analyze-email, and rendering the multi-domain forensic investigation results.
 *
 * NOTE: All risk scoring and point calculations occur EXCLUSIVELY on the backend.
 * This frontend contains zero scoring or risk formula logic.
 */

let selectedEmailFile = null;

function handleEmailDrop(e) {
  e.preventDefault();
  const dropzone = document.getElementById('email-dropzone');
  if (dropzone) {
    dropzone.style.borderColor = 'var(--border-color)';
    dropzone.style.background = 'var(--cream-light)';
  }

  if (e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files.length > 0) {
    processEmailFileSelection(e.dataTransfer.files[0]);
  }
}

function onEmailFileSelect(e) {
  if (e.target && e.target.files && e.target.files.length > 0) {
    processEmailFileSelection(e.target.files[0]);
  }
}

function processEmailFileSelection(file) {
  const statusEl = document.getElementById('email-status');
  const filename = file.name || 'message.eml';
  const ext = filename.toLowerCase().split('.').pop();

  if (ext !== 'eml') {
    if (statusEl) {
      statusEl.style.color = 'var(--coral)';
      statusEl.textContent = '❌ Unsupported file format. Please select an .eml RFC 5322 email file.';
    }
    return;
  }

  if (file.size > 10 * 1024 * 1024) {
    if (statusEl) {
      statusEl.style.color = 'var(--coral)';
      statusEl.textContent = '❌ File exceeds maximum upload limit of 10 MB.';
    }
    return;
  }

  selectedEmailFile = file;

  // Update UI with file info
  const infoWrap = document.getElementById('email-file-info-wrap');
  const filenameDisp = document.getElementById('email-filename-display');
  const filesizeDisp = document.getElementById('email-filesize-display');
  const clearBtn = document.getElementById('email-clear-btn');

  if (infoWrap) infoWrap.style.display = 'inline-block';
  if (filenameDisp) filenameDisp.textContent = filename;
  if (filesizeDisp) filesizeDisp.textContent = (file.size / 1024).toFixed(1) + ' KB';
  if (clearBtn) clearBtn.style.display = 'inline-block';

  // Automatically start analysis
  uploadAndAnalyzeEmail(file);
}

function clearEmailUpload() {
  selectedEmailFile = null;
  const fileInput = document.getElementById('email-file-input');
  if (fileInput) fileInput.value = '';

  const infoWrap = document.getElementById('email-file-info-wrap');
  if (infoWrap) infoWrap.style.display = 'none';

  const clearBtn = document.getElementById('email-clear-btn');
  if (clearBtn) clearBtn.style.display = 'none';

  const statusEl = document.getElementById('email-status');
  if (statusEl) {
    statusEl.textContent = '';
    statusEl.style.color = 'inherit';
  }

  const resultSec = document.getElementById('email-result-section');
  if (resultSec) resultSec.style.display = 'none';
}

async function uploadAndAnalyzeEmail(file) {
  const statusEl = document.getElementById('email-status');
  const resultSec = document.getElementById('email-result-section');

  if (statusEl) {
    statusEl.style.color = 'var(--teal)';
    statusEl.innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> Parsing RFC 5322 headers, authenticating SPF/DKIM/DMARC, cascading embedded links...';
  }

  const formData = new FormData();
  formData.append('file', file);

  try {
    const response = await fetch('/api/analyze-email', {
      method: 'POST',
      body: formData
    });

    const data = await response.json();

    if (!response.ok || !data.success) {
      const errMsg = data.error || 'Failed to analyze email file.';
      if (statusEl) {
        statusEl.style.color = 'var(--coral)';
        statusEl.textContent = '❌ ' + errMsg;
      }
      return;
    }

    if (statusEl) {
      statusEl.style.color = '#2e7d32';
      statusEl.textContent = '✓ Email investigation complete.';
    }

    renderEmailResults(data.data);
    if (resultSec) {
      resultSec.style.display = 'block';
      resultSec.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }

  } catch (err) {
    console.error('Email analysis error:', err);
    if (statusEl) {
      statusEl.style.color = 'var(--coral)';
      statusEl.textContent = '❌ Network or server error during email analysis.';
    }
  }
}

function renderEmailResults(res) {
  if (!res) return;

  const riskScore = res.risk_score || 0;
  const riskLevel = res.risk_level || 'Low';
  const prediction = res.prediction || 'Legitimate';
  const ea = res.email_analysis || {};
  const exp = res.explanation || {};
  const bd = res.risk_breakdown || {};

  // 1. Risk Hero Gauge
  const circleEl = document.getElementById('email-risk-circle');
  const scoreEl = document.getElementById('email-risk-score');
  const levelEl = document.getElementById('email-risk-level');
  const badgeEl = document.getElementById('email-verdict-badge');
  const predTextEl = document.getElementById('email-prediction-text');
  const recEl = document.getElementById('email-recommendation');

  if (circleEl) {
    circleEl.className = 'risk-circle ' + riskLevel;
  }
  if (scoreEl) scoreEl.textContent = riskScore;
  if (levelEl) {
    levelEl.className = 'badge-risk-level ' + riskLevel;
    levelEl.textContent = riskLevel + ' Risk';
  }
  if (badgeEl) {
    badgeEl.className = 'verdict-badge ' + prediction;
    badgeEl.textContent = prediction.toUpperCase();
  }
  if (predTextEl) {
    predTextEl.textContent = (prediction === 'Phishing'
      ? 'High probability of spear-phishing or credential manipulation.'
      : (prediction === 'Suspicious'
        ? 'Elevated suspicion due to structural or linguistic anomalies.'
        : 'Legitimate email profile based on evaluated characteristics.'));
  }
  if (recEl) {
    recEl.textContent = res.recommendation || 'No recommendation provided.';
  }

  // 2. Sender Forensics
  const headers = ea.headers || {};
  const domains = ea.domains || {};
  const hdrPtsBadge = document.getElementById('email-header-pts-badge');
  if (hdrPtsBadge) {
    hdrPtsBadge.textContent = (bd.header_points || 0) + ' / 20 pts';
  }

  const senderVal = document.getElementById('email-sender-val');
  const senderDom = document.getElementById('email-sender-domain');
  if (senderVal) senderVal.textContent = headers.from || 'Not specified';
  if (senderDom) senderDom.textContent = domains.sender_domain || 'Unknown';

  const replytoVal = document.getElementById('email-replyto-val');
  const replytoDom = document.getElementById('email-replyto-domain');
  if (replytoVal) replytoVal.textContent = headers.reply_to || 'None (matches From)';
  if (replytoDom) replytoDom.textContent = domains.reply_to_domain || 'None';

  const returnpathVal = document.getElementById('email-returnpath-val');
  const returnpathDom = document.getElementById('email-returnpath-domain');
  if (returnpathVal) returnpathVal.textContent = headers.return_path || 'Not specified';
  if (returnpathDom) returnpathDom.textContent = domains.return_path_domain || 'Unknown';

  // Header indicators
  const hdrList = document.getElementById('email-header-indicators-list');
  if (hdrList) {
    hdrList.innerHTML = '';
    const inds = ea.header_indicators || [];
    if (inds.length === 0) {
      hdrList.innerHTML = '<div style="font-size:12px; color:var(--text-secondary); font-style:italic;">No header anomalies detected.</div>';
    } else {
      inds.forEach(ind => {
        const item = document.createElement('div');
        item.style.padding = '8px 12px';
        item.style.background = '#fff';
        item.style.borderLeft = '3px solid var(--coral)';
        item.style.borderRadius = '3px';
        item.style.fontSize = '12px';
        item.innerHTML = `<strong>${escapeHtml(ind.name)}</strong> (+${ind.points} pts)<br><span style="color:var(--text-secondary);">${escapeHtml(ind.description)}</span>`;
        hdrList.appendChild(item);
      });
    }
  }

  // 3. Authentication
  const auth = ea.authentication || {};
  const authPtsBadge = document.getElementById('email-auth-pts-badge');
  if (authPtsBadge) {
    authPtsBadge.textContent = (bd.auth_points || 0) + ' / 20 pts';
  }

  renderAuthBadge('email-auth-spf-badge', auth.spf);
  renderAuthBadge('email-auth-dkim-badge', auth.dkim);
  renderAuthBadge('email-auth-dmarc-badge', auth.dmarc);

  const authList = document.getElementById('email-auth-indicators-list');
  if (authList) {
    authList.innerHTML = '';
    const authInds = auth.indicators || [];
    if (authInds.length === 0) {
      authList.innerHTML = '<div style="font-size:12px; color:var(--text-secondary); font-style:italic;">No authentication failures detected.</div>';
    } else {
      authInds.forEach(ind => {
        const item = document.createElement('div');
        item.style.padding = '8px 12px';
        item.style.background = '#fff';
        item.style.borderLeft = '3px solid var(--coral)';
        item.style.borderRadius = '3px';
        item.style.fontSize = '12px';
        item.innerHTML = `<strong>${escapeHtml(ind.name)}</strong> (+${ind.points} pts)<br><span style="color:var(--text-secondary);">${escapeHtml(ind.description)}</span>`;
        authList.appendChild(item);
      });
    }
  }

  // 4. Subject Analysis
  const subjPtsBadge = document.getElementById('email-subject-pts-badge');
  if (subjPtsBadge) {
    subjPtsBadge.textContent = (bd.subject_points || 0) + ' / 15 pts';
  }

  const subjVal = document.getElementById('email-subject-val');
  if (subjVal) subjVal.textContent = headers.subject || '(No Subject)';

  const subjList = document.getElementById('email-subject-indicators-list');
  if (subjList) {
    subjList.innerHTML = '';
    const subjInds = ea.subject_indicators || [];
    if (subjInds.length === 0) {
      subjList.innerHTML = '<div style="font-size:12px; color:var(--text-secondary); font-style:italic;">No high-pressure or social engineering keywords found in subject.</div>';
    } else {
      subjInds.forEach(ind => {
        const item = document.createElement('div');
        item.style.padding = '8px 12px';
        item.style.background = '#fff';
        item.style.borderLeft = '3px solid var(--coral)';
        item.style.borderRadius = '3px';
        item.style.fontSize = '12px';
        item.innerHTML = `<strong>${escapeHtml(ind.name)}</strong> (+${ind.points} pts)<br><span style="color:var(--text-secondary);">${escapeHtml(ind.description)}</span>`;
        subjList.appendChild(item);
      });
    }
  }

  // 5. Body & Classifier Proxy
  const bodyPtsBadge = document.getElementById('email-body-pts-badge');
  if (bodyPtsBadge) {
    bodyPtsBadge.textContent = (bd.body_ml_points || 0) + ' / 30 pts';
  }

  const bodyMlProb = document.getElementById('email-body-ml-prob');
  if (bodyMlProb) {
    const prob = ea.body_ml_proxy ? ea.body_ml_proxy.probability : null;
    bodyMlProb.textContent = prob !== null && prob !== undefined ? (prob * 100).toFixed(1) + '%' : 'Offline';
  }

  const bodyList = document.getElementById('email-body-indicators-list');
  if (bodyList) {
    bodyList.innerHTML = '';
    const bodyInds = ea.body_indicators || [];
    if (bodyInds.length === 0) {
      bodyList.innerHTML = '<div style="font-size:12px; color:var(--text-secondary); font-style:italic;">No significant social engineering patterns identified in body.</div>';
    } else {
      bodyInds.forEach(ind => {
        const item = document.createElement('div');
        item.style.padding = '8px 12px';
        item.style.background = '#fff';
        item.style.borderLeft = '3px solid var(--terracotta)';
        item.style.borderRadius = '3px';
        item.style.fontSize = '12px';
        item.innerHTML = `<strong>${escapeHtml(ind.name)}</strong> (severity: ${escapeHtml(ind.severity)})<br><span style="color:var(--text-secondary);">${escapeHtml(ind.description)}</span>`;
        bodyList.appendChild(item);
      });
    }
  }

  // HTML Security Flags
  const htmlSecWrap = document.getElementById('email-html-security-wrap');
  const htmlSecList = document.getElementById('email-html-security-list');
  const htmlFlags = ea.html_security_flags || [];
  if (htmlSecWrap && htmlSecList) {
    if (htmlFlags.length > 0) {
      htmlSecWrap.style.display = 'block';
      htmlSecList.innerHTML = '';
      htmlFlags.forEach(flag => {
        const item = document.createElement('div');
        item.style.padding = '8px 12px';
        item.style.background = '#ffebee';
        item.style.borderLeft = '3px solid #d32f2f';
        item.style.borderRadius = '3px';
        item.style.fontSize = '12px';
        item.innerHTML = `<strong>${escapeHtml(flag.type)}</strong>: ${escapeHtml(flag.description)}`;
        htmlSecList.appendChild(item);
      });
    } else {
      htmlSecWrap.style.display = 'none';
    }
  }

  // 6. Extracted URLs
  const urlPtsBadge = document.getElementById('email-url-pts-badge');
  if (urlPtsBadge) {
    urlPtsBadge.textContent = (bd.url_cascade_points || 0) + ' / 20 pts';
  }

  const urlList = document.getElementById('email-urls-list');
  if (urlList) {
    urlList.innerHTML = '';
    const urls = ea.extracted_urls || [];
    if (urls.length === 0) {
      urlList.innerHTML = '<div style="font-size:12px; color:var(--text-secondary); font-style:italic;">No embedded hyperlinks found in message body.</div>';
    } else {
      urls.forEach(u => {
        const card = document.createElement('div');
        card.style.background = 'var(--cream-dark)';
        card.style.border = '1px solid var(--border-color)';
        card.style.borderRadius = 'var(--radius-sm)';
        card.style.padding = '12px';
        card.style.display = 'flex';
        card.style.justifyContent = 'space-between';
        card.style.alignItems = 'center';
        card.style.flexWrap = 'wrap';
        card.style.gap = '8px';

        let tiSummary = '';
        if (u.threat_intelligence && u.threat_intelligence.enabled) {
          const sum = u.threat_intelligence.summary || {};
          if (sum.status === 'success') {
            tiSummary = `<span style="font-size:11px; color:${sum.detections > 0 ? 'var(--coral)' : '#2e7d32'}; font-weight:700;">VirusTotal: ${sum.detections}/${sum.total_engines}</span>`;
          }
        }

        card.innerHTML = `
          <div style="flex:1; min-width:200px;">
            <div style="font-size:12px; font-weight:700; color:var(--teal); word-break:break-all;">${escapeHtml(u.url)}</div>
            <div style="font-size:11px; color:var(--text-secondary); margin-top:2px;">
              Verdict: <strong>${escapeHtml(u.prediction || 'Unknown')}</strong> ${tiSummary}
            </div>
          </div>
          <div style="text-align:right;">
            <span class="badge-risk-level ${u.risk_level || 'Low'}" style="font-size:11px; padding:3px 8px;">
              ${u.risk_score}/100 · ${u.risk_level}
            </span>
          </div>
        `;
        urlList.appendChild(card);
      });
    }
  }

  // 7. Attachments
  const attPtsBadge = document.getElementById('email-att-pts-badge');
  if (attPtsBadge) {
    attPtsBadge.textContent = (bd.attachment_points || 0) + ' / 15 pts';
  }

  const attList = document.getElementById('email-attachments-list');
  if (attList) {
    attList.innerHTML = '';
    const atts = ea.attachments || [];
    if (atts.length === 0) {
      attList.innerHTML = '<div style="font-size:12px; color:var(--text-secondary); font-style:italic;">No attachments detected in this message.</div>';
    } else {
      atts.forEach(att => {
        const item = document.createElement('div');
        item.style.background = 'var(--cream-dark)';
        item.style.border = '1px solid var(--border-color)';
        item.style.borderRadius = 'var(--radius-sm)';
        item.style.padding = '10px 14px';
        item.style.display = 'flex';
        item.style.justifyContent = 'space-between';
        item.style.alignItems = 'center';
        item.style.flexWrap = 'wrap';
        item.style.gap = '8px';

        const isRisky = att.risk_category !== 'benign';
        item.innerHTML = `
          <div>
            <div style="font-size:12px; font-weight:700; color:var(--teal);">📎 ${escapeHtml(att.filename)}</div>
            <div style="font-size:11px; color:var(--text-secondary);">
              Type: ${escapeHtml(att.content_type || 'Unknown')} · Size: ${(att.size / 1024).toFixed(1)} KB · Disp: ${escapeHtml(att.disposition)}
            </div>
          </div>
          <div>
            <span style="font-size:11px; font-weight:700; padding:3px 8px; border-radius:3px; background:${isRisky ? '#ffebee' : '#e8f5e9'}; color:${isRisky ? 'var(--coral)' : '#2e7d32'};">
              ${escapeHtml(att.risk_note)}
            </span>
          </div>
        `;
        attList.appendChild(item);
      });
    }
  }

  const attIndsWrap = document.getElementById('email-att-indicators-wrap');
  const attIndsList = document.getElementById('email-att-indicators-list');
  const attInds = ea.attachment_indicators || [];
  if (attIndsWrap && attIndsList) {
    if (attInds.length > 0) {
      attIndsWrap.style.display = 'block';
      attIndsList.innerHTML = '';
      attInds.forEach(ind => {
        const item = document.createElement('div');
        item.style.padding = '8px 12px';
        item.style.background = '#fff';
        item.style.borderLeft = '3px solid var(--coral)';
        item.style.borderRadius = '3px';
        item.style.fontSize = '12px';
        item.innerHTML = `<strong>${escapeHtml(ind.name)}</strong> (+${ind.points} pts): ${escapeHtml(ind.description)}`;
        attIndsList.appendChild(item);
      });
    } else {
      attIndsWrap.style.display = 'none';
    }
  }

  // 8. Breakdown
  setMetricText('email-breakdown-hdr', bd.header_points || 0);
  setMetricText('email-breakdown-auth', bd.auth_points || 0);
  setMetricText('email-breakdown-subj', bd.subject_points || 0);
  setMetricText('email-breakdown-body', bd.body_ml_points || 0);
  setMetricText('email-breakdown-att', bd.attachment_points || 0);
  setMetricText('email-breakdown-url', bd.url_cascade_points || 0);

  const formulaEl = document.getElementById('email-formula-display');
  if (formulaEl) {
    formulaEl.textContent = bd.formula || 'Formula: Final Risk Score = min(100, Header + Auth + Subject + Body + Attachment + URL_Cascade)';
  }

  // 9. Timeline
  const timelineList = document.getElementById('email-timeline-list');
  if (timelineList) {
    timelineList.innerHTML = '';
    const stages = exp.investigation_stages || [];
    stages.forEach((stg, idx) => {
      const row = document.createElement('div');
      row.style.display = 'flex';
      row.style.gap = '12px';
      row.style.alignItems = 'flex-start';

      row.innerHTML = `
        <div style="background:var(--teal); color:#fff; width:22px; height:22px; border-radius:50%; display:flex; align-items:center; justify-content:center; font-size:11px; font-weight:700; flex-shrink:0; margin-top:2px;">
          ${idx + 1}
        </div>
        <div style="flex:1;">
          <div style="font-size:12px; font-weight:700; color:var(--teal);">${escapeHtml(stg.stage)}</div>
          <div style="font-size:12px; color:var(--text-secondary); line-height:1.4;">${escapeHtml(stg.detail)}</div>
        </div>
      `;
      timelineList.appendChild(row);
    });
  }
}

function renderAuthBadge(elementId, status) {
  const el = document.getElementById(elementId);
  if (!el) return;
  const s = (status || 'not_present').toLowerCase();
  el.textContent = s.toUpperCase();

  if (s === 'pass') {
    el.style.background = '#e8f5e9';
    el.style.color = '#2e7d32';
  } else if (s === 'fail' || s === 'permerror') {
    el.style.background = '#ffebee';
    el.style.color = 'var(--coral)';
  } else if (s === 'softfail' || s === 'neutral') {
    el.style.background = '#fff3e0';
    el.style.color = '#e65100';
  } else {
    el.style.background = '#eeeeee';
    el.style.color = '#757575';
  }
}

function setMetricText(id, val) {
  const el = document.getElementById(id);
  if (el) el.textContent = val;
}

function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}
