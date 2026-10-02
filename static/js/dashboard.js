/**
 * dashboard.js - Chart.js Telemetry & Real-Time Stats Loader
 * PhishGuard AI — Editorial Security Theme
 * Palette: Coral #E64833, Terracotta #874F41, Teal #244855, Aqua #90AEAD, Cream #FBE9D0
 */

let distChart       = null;
let riskChart       = null;
let timelineChart   = null;
let indicatorsChart = null;

// Theme palette constants (must match CSS vars)
const C = {
  coral:      '#E64833',
  terracotta: '#874F41',
  teal:       '#244855',
  aqua:       '#90AEAD',
  cream:      '#FBE9D0',
  creamDark:  '#f0d9ba',
  border:     '#d4bfa0',
  textMuted:  '#7a8f8e',
  textSec:    '#4a6970',
};

const CHART_DEFAULTS = {
  responsive: true,
  maintainAspectRatio: false,
  plugins: {
    legend: {
      labels: {
        color: C.textSec,
        font: { family: "'DM Sans', system-ui, sans-serif", size: 12 },
        padding: 16
      }
    }
  }
};

async function fetchDashboardStats() {
  try {
    const res  = await fetch('/api/dashboard-stats');
    const json = await res.json();
    if (!json.success) return;

    const data  = json.data;
    const total = data.total_scans || 0;

    document.getElementById('stat-total').textContent =
      total;
    document.getElementById('stat-phish').textContent =
      (data.predictions && data.predictions.phishing !== undefined)
        ? data.predictions.phishing : (data.phishing_detected || 0);
    document.getElementById('stat-legit').textContent =
      (data.predictions && data.predictions.legitimate !== undefined)
        ? data.predictions.legitimate : (data.legitimate || 0);
    document.getElementById('stat-susp').textContent =
      (data.predictions && data.predictions.suspicious !== undefined)
        ? data.predictions.suspicious : (data.suspicious || 0);
    document.getElementById('stat-avg-risk').textContent =
      (data.average_risk_score !== undefined ? data.average_risk_score : 0) + '/100';

    // Database badge
    const dbBadge = document.getElementById('db-backend-badge');
    if (dbBadge) {
      if (!data.mongodb_connected) {
        dbBadge.textContent         = '● In-Memory Fallback';
        dbBadge.style.borderColor   = C.terracotta;
        dbBadge.style.color         = C.terracotta;
        dbBadge.style.backgroundColor = 'rgba(135,79,65,0.1)';
      } else {
        dbBadge.textContent         = '● MongoDB Online';
        dbBadge.style.borderColor   = C.teal;
        dbBadge.style.color         = C.teal;
        dbBadge.style.backgroundColor = 'rgba(36,72,85,0.1)';
      }
    }

    renderDistributionChart(data.predictions || data.prediction_distribution || {}, total);
    renderRiskDistributionChart(data.risk_levels || {}, total);
    renderTimelineChart(data.scans_over_time || [], total);
    renderTopIndicatorsChart(data.top_indicators || [], total);

  } catch (err) {
    console.error('Dashboard stats error:', err);
  }
}

function renderDistributionChart(predictions, totalScans) {
  const emptyEl = document.getElementById('empty-dist');
  const wrapEl  = document.getElementById('wrap-dist');
  const ctx     = document.getElementById('chart-distribution');
  if (!ctx) return;

  if (totalScans === 0) {
    if (emptyEl) emptyEl.style.display = 'flex';
    if (wrapEl)  wrapEl.style.display  = 'none';
    if (distChart) { distChart.destroy(); distChart = null; }
    return;
  }

  if (emptyEl) emptyEl.style.display = 'none';
  if (wrapEl)  wrapEl.style.display  = 'block';

  const phishCount = predictions.phishing   !== undefined ? predictions.phishing   : (predictions['Phishing']   || 0);
  const legitCount = predictions.legitimate !== undefined ? predictions.legitimate : (predictions['Legitimate'] || 0);
  const suspCount  = predictions.suspicious !== undefined ? predictions.suspicious : (predictions['Suspicious'] || 0);

  if (distChart) distChart.destroy();

  distChart = new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels: ['Phishing', 'Suspicious', 'Legitimate'],
      datasets: [{
        data: [phishCount, suspCount, legitCount],
        backgroundColor: [C.coral, C.terracotta, C.aqua],
        borderColor:     [C.creamDark, C.creamDark, C.creamDark],
        borderWidth: 3
      }]
    },
    options: {
      ...CHART_DEFAULTS,
      plugins: {
        ...CHART_DEFAULTS.plugins,
        legend: { ...CHART_DEFAULTS.plugins.legend, position: 'bottom' }
      }
    }
  });
}

function renderRiskDistributionChart(riskLevels, totalScans) {
  const emptyEl = document.getElementById('empty-risk');
  const wrapEl  = document.getElementById('wrap-risk');
  const ctx     = document.getElementById('chart-risk-distribution');
  if (!ctx) return;

  if (totalScans === 0) {
    if (emptyEl) emptyEl.style.display = 'flex';
    if (wrapEl)  wrapEl.style.display  = 'none';
    if (riskChart) { riskChart.destroy(); riskChart = null; }
    return;
  }

  if (emptyEl) emptyEl.style.display = 'none';
  if (wrapEl)  wrapEl.style.display  = 'block';

  if (riskChart) riskChart.destroy();

  riskChart = new Chart(ctx, {
    type: 'bar',
    data: {
      labels: ['Low\n(0–24)', 'Medium\n(25–54)', 'High\n(55–79)', 'Critical\n(80–100)'],
      datasets: [{
        label: 'Scans',
        data: [
          riskLevels.low      || 0,
          riskLevels.medium   || 0,
          riskLevels.high     || 0,
          riskLevels.critical || 0
        ],
        backgroundColor: [C.aqua, C.terracotta, C.coral, C.coral],
        borderRadius: 3
      }]
    },
    options: {
      ...CHART_DEFAULTS,
      scales: {
        x: { ticks: { color: C.textSec }, grid: { color: C.border, lineWidth: 0.5 } },
        y: { ticks: { color: C.textMuted, stepSize: 1 }, grid: { color: C.border, lineWidth: 0.5 } }
      },
      plugins: { ...CHART_DEFAULTS.plugins, legend: { display: false } }
    }
  });
}

function renderTimelineChart(timeline, totalScans) {
  const emptyEl = document.getElementById('empty-timeline');
  const wrapEl  = document.getElementById('wrap-timeline');
  const ctx     = document.getElementById('chart-timeline');
  if (!ctx) return;

  if (totalScans === 0) {
    if (emptyEl) emptyEl.style.display = 'flex';
    if (wrapEl)  wrapEl.style.display  = 'none';
    if (timelineChart) { timelineChart.destroy(); timelineChart = null; }
    return;
  }

  if (emptyEl) emptyEl.style.display = 'none';
  if (wrapEl)  wrapEl.style.display  = 'block';

  if (timelineChart) timelineChart.destroy();

  timelineChart = new Chart(ctx, {
    type: 'line',
    data: {
      labels: timeline.map(t => t.date.slice(5)),
      datasets: [{
        label: 'Scans',
        data: timeline.map(t => t.count),
        borderColor: C.teal,
        backgroundColor: 'rgba(36,72,85,0.08)',
        tension: 0.35,
        fill: true,
        pointBackgroundColor: C.coral,
        pointBorderColor:     C.cream,
        pointBorderWidth: 2,
        pointRadius: 4
      }]
    },
    options: {
      ...CHART_DEFAULTS,
      scales: {
        x: { ticks: { color: C.textSec  }, grid: { color: C.border, lineWidth: 0.5 } },
        y: { ticks: { color: C.textMuted, stepSize: 1 }, grid: { color: C.border, lineWidth: 0.5 } }
      },
      plugins: { ...CHART_DEFAULTS.plugins, legend: { display: false } }
    }
  });
}

function renderTopIndicatorsChart(indicators, totalScans) {
  const emptyEl = document.getElementById('empty-indicators');
  const wrapEl  = document.getElementById('wrap-indicators');
  const ctx     = document.getElementById('chart-indicators');
  if (!ctx) return;

  if (totalScans === 0 || !indicators || indicators.length === 0) {
    if (emptyEl) emptyEl.style.display = 'flex';
    if (wrapEl)  wrapEl.style.display  = 'none';
    if (indicatorsChart) { indicatorsChart.destroy(); indicatorsChart = null; }
    return;
  }

  if (emptyEl) emptyEl.style.display = 'none';
  if (wrapEl)  wrapEl.style.display  = 'block';

  if (indicatorsChart) indicatorsChart.destroy();

  indicatorsChart = new Chart(ctx, {
    type: 'bar',
    data: {
      labels: indicators.map(i => i.indicator.length > 30 ? i.indicator.slice(0, 27) + '…' : i.indicator),
      datasets: [{
        label: 'Trigger Count',
        data: indicators.map(i => i.count),
        backgroundColor: C.terracotta,
        borderRadius: 3
      }]
    },
    options: {
      indexAxis: 'y',
      ...CHART_DEFAULTS,
      scales: {
        x: { ticks: { color: C.textMuted, stepSize: 1 }, grid: { color: C.border, lineWidth: 0.5 } },
        y: { ticks: { color: C.textSec  }, grid: { display: false } }
      },
      plugins: { ...CHART_DEFAULTS.plugins, legend: { display: false } }
    }
  });
}

document.addEventListener('DOMContentLoaded', () => {
  if (document.getElementById('stat-total')) {
    fetchDashboardStats();
    setInterval(fetchDashboardStats, 30000);
  }
});
