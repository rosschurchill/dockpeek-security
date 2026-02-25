import { apiUrl } from './config.js';

export function initApiKeys() {
  const button = document.getElementById('api-keys-button');
  const modal = document.getElementById('api-keys-modal');
  const closeBtn = document.getElementById('api-keys-modal-close');
  const okBtn = document.getElementById('api-keys-modal-ok');

  if (!button || !modal) return;

  button.addEventListener('click', () => {
    openModal();
  });

  closeBtn?.addEventListener('click', closeModal);
  okBtn?.addEventListener('click', closeModal);

  modal.addEventListener('click', (e) => {
    if (e.target === modal) closeModal();
  });

  document.getElementById('api-key-create-btn')?.addEventListener('click', handleCreate);
  document.getElementById('api-key-copy-btn')?.addEventListener('click', handleCopy);

  function closeModal() {
    modal.classList.add('hidden');
    hideBanner();
  }

  function hideBanner() {
    const banner = document.getElementById('api-key-created-banner');
    if (banner) banner.classList.add('hidden');
    const plaintext = document.getElementById('api-key-plaintext');
    if (plaintext) plaintext.textContent = '';
  }

  async function openModal() {
    modal.classList.remove('hidden');
    hideBanner();
    await loadKeys();
  }

  async function loadKeys() {
    const listEl = document.getElementById('api-keys-list');
    if (!listEl) return;

    listEl.innerHTML = '<div class="api-keys-loading">Loading keys...</div>';

    try {
      const res = await fetch(apiUrl('/api/keys'));
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const keys = await res.json();
      renderKeyList(listEl, keys);
    } catch {
      listEl.innerHTML = '<div class="api-keys-empty">Could not load API keys.</div>';
    }
  }

  function renderKeyList(container, keys) {
    if (!keys || keys.length === 0) {
      container.innerHTML = '<div class="api-keys-empty">No API keys yet. Create one above.</div>';
      return;
    }

    container.innerHTML = keys.map((key) => {
      const status = getKeyStatus(key);
      const badgeClass = `api-key-badge api-key-badge-${status.toLowerCase()}`;
      const createdDate = formatDate(key.created_at);
      const expiryDate = key.expires_at ? formatDate(key.expires_at) : 'Never';
      const lastUsed = key.last_used_at ? formatDate(key.last_used_at) : 'Never';
      const revokeBtn = status === 'Active'
        ? `<button class="api-key-revoke-btn" data-key-id="${escapeAttr(key.id)}">Revoke</button>`
        : '';

      return `
        <div class="api-key-row">
          <span class="api-key-prefix" title="Key prefix">${escapeHtml(key.prefix || '')}...</span>
          <span class="api-key-label">${escapeHtml(key.label || 'Unnamed')}</span>
          <span class="api-key-meta" title="Created">${createdDate}</span>
          <span class="api-key-meta" title="Expires">${expiryDate}</span>
          <span class="api-key-meta" title="Last used">${lastUsed}</span>
          <span class="${badgeClass}">${status}</span>
          ${revokeBtn}
        </div>`;
    }).join('');

    container.querySelectorAll('.api-key-revoke-btn').forEach((btn) => {
      btn.addEventListener('click', () => handleRevoke(btn.dataset.keyId));
    });
  }

  function getKeyStatus(key) {
    if (key.revoked) return 'Revoked';
    if (key.expires_at && new Date(key.expires_at) < new Date()) return 'Expired';
    return 'Active';
  }

  function formatDate(isoString) {
    if (!isoString) return '—';
    const d = new Date(isoString);
    if (isNaN(d.getTime())) return '—';
    return d.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
  }

  async function handleCreate() {
    const labelInput = document.getElementById('api-key-label');
    const expirySelect = document.getElementById('api-key-expiry');
    const createBtn = document.getElementById('api-key-create-btn');

    const label = labelInput?.value.trim() || '';
    const expiresIn = expirySelect ? parseInt(expirySelect.value, 10) : 604800;

    if (!label) {
      labelInput?.focus();
      labelInput?.classList.add('api-key-input-error');
      setTimeout(() => labelInput?.classList.remove('api-key-input-error'), 1500);
      return;
    }

    if (createBtn) {
      createBtn.disabled = true;
      createBtn.textContent = 'Creating...';
    }

    try {
      const res = await fetch(apiUrl('/api/keys'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ label, expires_in: expiresIn }),
      });

      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();

      showBanner(data.key || data.plaintext_key || '');

      if (labelInput) labelInput.value = '';
      await loadKeys();
    } catch {
      showError('Failed to create key. Please try again.');
    } finally {
      if (createBtn) {
        createBtn.disabled = false;
        createBtn.textContent = 'Create Key';
      }
    }
  }

  function showBanner(plaintext) {
    const banner = document.getElementById('api-key-created-banner');
    const code = document.getElementById('api-key-plaintext');
    if (!banner || !code) return;
    code.textContent = plaintext;
    banner.classList.remove('hidden');
    banner.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  }

  async function handleCopy() {
    const code = document.getElementById('api-key-plaintext');
    const copyBtn = document.getElementById('api-key-copy-btn');
    if (!code || !copyBtn) return;

    const text = code.textContent;
    if (!text) return;

    try {
      await navigator.clipboard.writeText(text);
      const original = copyBtn.textContent;
      copyBtn.textContent = 'Copied!';
      setTimeout(() => { copyBtn.textContent = original; }, 2000);
    } catch {
      showError('Could not copy to clipboard.');
    }
  }

  async function handleRevoke(keyId) {
    if (!keyId) return;

    try {
      const res = await fetch(apiUrl(`/api/keys/${keyId}`), { method: 'DELETE' });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      await loadKeys();
    } catch {
      showError('Failed to revoke key. Please try again.');
    }
  }

  function showError(message) {
    const listEl = document.getElementById('api-keys-list');
    if (!listEl) return;
    const err = document.createElement('div');
    err.className = 'api-keys-empty';
    err.style.color = '#ef4444';
    err.textContent = message;
    listEl.prepend(err);
    setTimeout(() => err.remove(), 4000);
  }

  function escapeHtml(str) {
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  function escapeAttr(str) {
    return String(str).replace(/"/g, '&quot;');
  }
}
