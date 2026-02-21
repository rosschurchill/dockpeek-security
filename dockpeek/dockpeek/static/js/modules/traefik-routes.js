const API_PREFIX = document.querySelector('meta[name="api-prefix"]')?.content || '';

export function initTraefikRoutes() {
  const button = document.getElementById('traefik-routes-button');
  const modal = document.getElementById('traefik-routes-modal');
  const closeBtn = document.getElementById('traefik-modal-close');
  const okBtn = document.getElementById('traefik-modal-ok');

  if (button) {
    button.addEventListener('click', showTraefikRoutes);
  }

  if (closeBtn) {
    closeBtn.addEventListener('click', closeModal);
  }

  if (okBtn) {
    okBtn.addEventListener('click', closeModal);
  }

  if (modal) {
    modal.addEventListener('click', (e) => {
      if (e.target === modal) closeModal();
    });
  }
}

async function showTraefikRoutes() {
  const modal = document.getElementById('traefik-routes-modal');
  const listEl = document.getElementById('traefik-routes-list');

  if (modal) modal.classList.remove('hidden');
  if (listEl) listEl.innerHTML = '<div class="text-center text-gray-500 py-8">Loading routes...</div>';

  try {
    const response = await fetch(`${API_PREFIX}/api/traefik/routes`);
    const data = await response.json();

    if (!data.enabled) {
      listEl.innerHTML = `
        <div class="text-center py-8">
          <p class="text-gray-500 mb-2">Traefik API not configured</p>
          <p class="text-sm text-gray-400">Set <code class="bg-gray-100 px-1 rounded">TRAEFIK_API_URL</code> environment variable</p>
          <p class="text-sm text-gray-400 mt-1">Example: <code class="bg-gray-100 px-1 rounded">http://traefik:8080</code></p>
        </div>
      `;
      return;
    }

    if (!data.routes || data.routes.length === 0) {
      listEl.innerHTML = `
        <div class="text-center py-8 text-gray-500">
          No routes found
        </div>
      `;
      return;
    }

    // Group routes by provider
    const routesByProvider = {};
    for (const route of data.routes) {
      const provider = route.provider || 'unknown';
      if (!routesByProvider[provider]) {
        routesByProvider[provider] = [];
      }
      routesByProvider[provider].push(route);
    }

    // Sort routes within each provider by URL
    for (const provider in routesByProvider) {
      routesByProvider[provider].sort((a, b) => a.url.localeCompare(b.url));
    }

    let html = '';

    // Show file provider routes first (these are the ones missing from container labels)
    const providerOrder = ['file@file', 'file', 'docker@docker', 'docker'];
    const sortedProviders = Object.keys(routesByProvider).sort((a, b) => {
      const aIndex = providerOrder.findIndex(p => a.includes(p));
      const bIndex = providerOrder.findIndex(p => b.includes(p));
      if (aIndex === -1 && bIndex === -1) return a.localeCompare(b);
      if (aIndex === -1) return 1;
      if (bIndex === -1) return -1;
      return aIndex - bIndex;
    });

    for (const provider of sortedProviders) {
      const routes = routesByProvider[provider];
      const providerLabel = provider.includes('file') ? '📁 File Provider' :
                           provider.includes('docker') ? '🐳 Docker Provider' :
                           `📦 ${provider}`;

      html += `
        <div class="mb-4">
          <h4 class="text-sm font-semibold text-gray-600 mb-2 px-2">${providerLabel} (${routes.length})</h4>
          <div class="space-y-1">
      `;

      for (const route of routes) {
        const statusClass = route.status === 'enabled' ? 'text-green-600' : 'text-gray-400';
        html += `
          <div class="flex items-center justify-between p-2 hover:bg-gray-50 rounded">
            <div class="flex-1 min-w-0">
              <a href="${route.url}" target="_blank" class="text-blue-600 hover:text-blue-800 text-sm truncate block">
                ${route.url}
              </a>
              <div class="text-xs text-gray-400 truncate">
                Service: ${route.service || 'N/A'} | Router: ${route.router || 'N/A'}
              </div>
            </div>
            <span class="text-xs ${statusClass} ml-2">${route.status || ''}</span>
          </div>
        `;
      }

      html += '</div></div>';
    }

    listEl.innerHTML = html;

  } catch (error) {
    console.error('Failed to fetch Traefik routes:', error);
    listEl.innerHTML = `
      <div class="text-center py-8 text-red-500">
        Failed to load routes: ${error.message}
      </div>
    `;
  }
}

function closeModal() {
  const modal = document.getElementById('traefik-routes-modal');
  if (modal) modal.classList.add('hidden');
}
