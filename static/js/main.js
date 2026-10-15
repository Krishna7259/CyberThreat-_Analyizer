// === CyberShield AI — Main JavaScript ===

// --- Sidebar Toggle ---
function toggleSidebar() {
  const sidebar = document.getElementById('sidebar');
  const wrapper = document.getElementById('mainWrapper');
  if (sidebar) sidebar.classList.toggle('collapsed');
  if (wrapper) wrapper.classList.toggle('expanded');
}

// --- Toast Notifications ---
function showToast(message, type = 'info', duration = 4000) {
  const icons = { success: 'fa-circle-check', error: 'fa-circle-xmark', warning: 'fa-triangle-exclamation', info: 'fa-circle-info' };
  const container = document.getElementById('toastContainer');
  if (!container) return;
  const toast = document.createElement('div');
  toast.className = `toast-item ${type}`;
  toast.innerHTML = `<i class="fas ${icons[type] || icons.info}"></i><span>${message}</span>`;
  container.appendChild(toast);
  setTimeout(() => { toast.style.opacity = '0'; toast.style.transform = 'translateX(30px)'; toast.style.transition = '0.3s'; setTimeout(() => toast.remove(), 300); }, duration);
}

// --- Loading Overlay ---
function showLoading(msg = 'Processing...') {
  let overlay = document.getElementById('loadingOverlay');
  if (!overlay) {
    overlay = document.createElement('div');
    overlay.className = 'loading-overlay';
    overlay.id = 'loadingOverlay';
    overlay.innerHTML = `<div class="spinner" style="width:48px;height:48px;border-width:4px;"></div><div style="color:var(--text-secondary);font-size:14px;">${msg}</div>`;
    document.body.appendChild(overlay);
  } else {
    overlay.querySelector('div:last-child').textContent = msg;
  }
  overlay.classList.add('active');
}
function hideLoading() {
  const overlay = document.getElementById('loadingOverlay');
  if (overlay) overlay.classList.remove('active');
}

// --- Severity Badge Helper ---
function severityBadge(severity) {
  const cls = { 'High': 'badge-high', 'Medium': 'badge-medium', 'Low': 'badge-low' }[severity] || 'badge-normal';
  return `<span class="badge-severity ${cls}">${severity}</span>`;
}

// --- Label Badge Helper ---
function labelBadge(label) {
  const cls = label === 'Suspicious' ? 'badge-suspicious' : 'badge-normal';
  return `<span class="badge-severity ${cls}">${label}</span>`;
}

// --- Format DateTime ---
function formatDate(iso) {
  if (!iso) return 'N/A';
  const d = new Date(iso);
  return d.toLocaleString('en-IN', { dateStyle: 'medium', timeStyle: 'short' });
}

// --- Number Format ---
function fmtNum(n) {
  return (n || 0).toLocaleString();
}

// --- CSRF fetch wrapper ---
async function csrfFetch(url, options = {}) {
  const headers = { 'Content-Type': 'application/json', ...(options.headers || {}) };
  return fetch(url, { ...options, headers });
}

// --- Score bar HTML ---
function scoreBar(score, cls) {
  const width = Math.min(100, Math.max(0, score));
  return `<div class="score-bar-wrap"><div class="score-bar"><div class="score-fill ${cls.toLowerCase()}" style="width:${width}%"></div></div><span style="font-size:11px;color:var(--text-muted)">${score.toFixed(1)}</span></div>`;
}
