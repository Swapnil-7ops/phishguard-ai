/**
 * main.js - Core UI helpers & Toast Notification System
 * PhishGuard AI — Editorial Security Theme
 */

function showToast(message, type = 'info') {
  let container = document.getElementById('toast-container');
  if (!container) {
    container = document.createElement('div');
    container.id = 'toast-container';
    container.className = 'toast-container';
    document.body.appendChild(container);
  }

  const toast = document.createElement('div');
  toast.className = 'toast';

  // Border-left color by type (using new palette vars)
  if (type === 'error')   toast.style.borderLeftColor = 'var(--coral)';
  if (type === 'success') toast.style.borderLeftColor = 'var(--aqua)';
  if (type === 'warning') toast.style.borderLeftColor = 'var(--terracotta)';

  toast.textContent = message;
  container.appendChild(toast);

  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transition = 'opacity 0.3s ease';
    setTimeout(() => toast.remove(), 300);
  }, 4000);
}

function setupAccordions() {
  document.querySelectorAll('.accordion-header').forEach(header => {
    header.addEventListener('click', () => {
      const accordion = header.closest('.accordion');
      accordion.classList.toggle('open');
      const arrow = header.querySelector('.accordion-arrow');
      if (arrow) {
        arrow.textContent = accordion.classList.contains('open') ? '▲' : '▼';
      }
    });
  });
}

/**
 * updateRiskGauge — updates the flat score panel
 * Preserves original function signature for full analyzer.js compatibility.
 * circleEl: the .risk-circle container
 * scoreEl:  the .risk-number element
 * badgeEl:  the .badge-risk-level element
 */
function updateRiskGauge(circleEl, scoreEl, badgeEl, score, level) {
  if (scoreEl) scoreEl.textContent = score;

  if (circleEl) {
    circleEl.className = 'risk-circle ' + level;

    // Update the horizontal risk bar width inside the panel
    const barFill = circleEl.querySelector('.risk-bar-fill');
    if (barFill) {
      barFill.style.width = Math.max(0, Math.min(100, score)) + '%';
    }
  }

  if (badgeEl) {
    badgeEl.className = 'badge-risk-level ' + level;
    badgeEl.textContent = level + ' Risk';
  }
}

document.addEventListener('DOMContentLoaded', () => {
  setupAccordions();

  // Highlight active sidebar nav link
  const currentPath = window.location.pathname;
  document.querySelectorAll('.nav-link').forEach(link => {
    const href = link.getAttribute('href');
    if (href === currentPath) {
      link.classList.add('active');
    } else {
      link.classList.remove('active');
    }
  });
});
