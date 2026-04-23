// ── Page navigation ───────────────────────────────────────────────
function showPage(id) {
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.nav-links a').forEach(a => a.classList.remove('active'));
  document.getElementById('page-' + id).classList.add('active');
  const navEl = document.getElementById('nav-' + id);
  if (navEl) navEl.classList.add('active');
  window.scrollTo(0, 0);
  return false;
}

function showPageAndScroll(pageId, targetId) {
  showPage(pageId);
  setTimeout(() => {
    const el = document.getElementById(targetId);
    if (el) {
      el.scrollIntoView({ behavior: 'smooth', block: 'start' });
      if (!el.hasAttribute('tabindex')) {
        el.setAttribute('tabindex', '-1');
      }
      el.focus({ preventScroll: true });
    }
  }, 60);
  return false;
}

// ── Language toggle ───────────────────────────────────────────────
function setLang(lang) {
  document.documentElement.setAttribute('data-lang', lang);
  document.querySelectorAll('.lang-btn').forEach((btn, i) => {
    btn.classList.toggle('active', (i === 0 && lang === 'en') || (i === 1 && lang === 'fr'));
  });
}

// ── Dark / Light theme toggle ─────────────────────────────────────
function toggleTheme() {
  const html = document.documentElement;
  const btn = document.getElementById('theme-toggle');
  const isLight = html.getAttribute('data-theme') === 'light';
  if (isLight) {
    html.removeAttribute('data-theme');
    btn.textContent = '☀ Light';
    localStorage.setItem('theme', 'dark');
  } else {
    html.setAttribute('data-theme', 'light');
    btn.textContent = '◑ Dark';
    localStorage.setItem('theme', 'light');
  }
}

// Restore saved theme on load
(function () {
  const saved = localStorage.getItem('theme');
  if (saved === 'light') {
    document.documentElement.setAttribute('data-theme', 'light');
    document.addEventListener('DOMContentLoaded', () => {
      const btn = document.getElementById('theme-toggle');
      if (btn) btn.textContent = '◑ Dark';
    });
  }
})();

// ── Setup option tabs ─────────────────────────────────────────────
function switchTab(id) {
  document.querySelectorAll('.option-tab').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.option-panel').forEach(p => p.classList.remove('active'));
  document.getElementById('tab-' + id).classList.add('active');
  const tabs = document.querySelectorAll('.option-tab');
  const idx = id === 'vm' ? 0 : 1;
  tabs[idx].classList.add('active');
}

// ── Navigate to a specific solution ──────────────────────────────
function showSolution(challengeId) {
  showPage('solutions');
  setTimeout(() => {
    const el = document.getElementById('sol-' + challengeId);
    if (el) el.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }, 60);
}
