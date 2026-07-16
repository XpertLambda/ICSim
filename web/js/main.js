// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2026 Xpert <ahmad.pc.saad@gmail.com> - IMT Atlantique, IoV Security Lab
// -- Page navigation -----------------------------------------------
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

// -- Language toggle -----------------------------------------------
function setLang(lang) {
  document.documentElement.setAttribute('data-lang', lang);
  document.querySelectorAll('.lang-btn').forEach((btn, i) => {
    btn.classList.toggle('active', (i === 0 && lang === 'en') || (i === 1 && lang === 'fr'));
  });
}

// -- Dark / Light theme toggle -------------------------------------
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

// -- Interactive setup guide: OS  →  delivery method ---------------
// Two-level chooser. Step 1 picks the OS (windows / linux / mac); step 2
// picks Docker or Virtual Machine. Docker has one panel per OS
// (panel-docker-<os>); the VM path shares a single panel (panel-vm) whose
// OS-specific opener is injected and whose Apple-Silicon (UTM / qcow2)
// block is revealed only for macOS.
let setupOS = 'windows';
let setupMethod = 'docker';

const VM_LEAD = {
  windows:
    '<span class="en">Install VirtualBox (or VMware), download the <code>.ova</code>, import it. No Docker, no WSL, fully offline.</span>' +
    '<span class="fr">Installez VirtualBox (ou VMware), téléchargez le <code>.ova</code>, importez-le. Sans Docker, sans WSL, hors ligne.</span>',
  linux:
    '<span class="en">Install VirtualBox (or VMware), download the <code>.ova</code>, import it. (Native Docker also runs well on Linux.)</span>' +
    '<span class="fr">Installez VirtualBox (ou VMware), téléchargez le <code>.ova</code>, importez-le. (Docker natif marche aussi bien sous Linux.)</span>',
  mac:
    '<span class="en">macOS splits by chip - <strong>Apple Silicon</strong> gets an arm64 image in UTM, <strong>Intel</strong> gets the x86 OVA. Pick yours below.</span>' +
    '<span class="fr">macOS se divise par puce - <strong>Apple Silicon</strong> reçoit une image arm64 dans UTM, <strong>Intel</strong> reçoit l\'OVA x86. Choisissez la vôtre ci-dessous.</span>'
};

function selectOS(os) {
  setupOS = os;
  document.querySelectorAll('#os-cards .method-card').forEach(c => c.classList.remove('active'));
  const card = document.getElementById('os-' + os);
  if (card) card.classList.add('active');
  // macOS: the VM path is recommended - flag it and default to it.
  const badge = document.getElementById('vm-rec-badge');
  if (badge) badge.style.display = (os === 'mac') ? '' : 'none';
  selectMethod(os === 'mac' ? 'vm' : setupMethod);
}

function selectMethod(method) {
  setupMethod = method;
  document.querySelectorAll('#method-cards .method-card').forEach(c => c.classList.remove('active'));
  const mcard = document.getElementById('method-' + method);
  if (mcard) mcard.classList.add('active');

  document.querySelectorAll('#page-setup .option-panel').forEach(p => p.classList.remove('active'));
  if (method === 'vm') {
    const isMac = (setupOS === 'mac');
    const lead = document.getElementById('vm-lead');
    if (lead) lead.innerHTML = VM_LEAD[setupOS] || VM_LEAD.windows;
    // Mac shows the Apple Silicon / Intel split; everyone else the single OVA flow.
    const macSplit = document.getElementById('vm-mac-split');
    const standard = document.getElementById('vm-standard');
    if (macSplit) macSplit.style.display = isMac ? 'block' : 'none';
    if (standard) standard.style.display = isMac ? 'none' : 'block';
    const p = document.getElementById('panel-vm');
    if (p) p.classList.add('active');
  } else {
    const p = document.getElementById('panel-docker-' + setupOS);
    if (p) p.classList.add('active');
  }
  // Keep the Usage page on the same environment the user just chose.
  selectEnv(method);
}

// -- Usage page: Docker vs VM environment --------------------------
// Mirrors the Step-2 choice above, but can be flipped independently
// (someone may read Usage before ever touching Installation).
function selectEnv(env) {
  document.querySelectorAll('#env-cards .method-card').forEach(c => c.classList.remove('active'));
  const card = document.getElementById('env-' + env);
  if (card) card.classList.add('active');
  document.querySelectorAll('#page-usage .option-panel').forEach(p => p.classList.remove('active'));
  const panel = document.getElementById('panel-env-' + env);
  if (panel) panel.classList.add('active');
}

// Seed the wizard on load (Windows + Docker) so a panel is always shown.
document.addEventListener('DOMContentLoaded', () => selectOS('windows'));

// -- Navigate to a specific solution ------------------------------
function showSolution(challengeId) {
  showPage('solutions');
  setTimeout(() => {
    const el = document.getElementById('sol-' + challengeId);
    if (el) el.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }, 60);
}
