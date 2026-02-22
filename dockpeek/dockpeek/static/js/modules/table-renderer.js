import * as CellRenderer from './cell-renderer.js';
import { getRegistryUrl } from './registry-urls.js';
import { renderStatus } from './status-renderer.js';
import { state } from './state.js';
import { escapeHtml } from './utils/sanitize.js';


export class TableRenderer {
  constructor(templateId, bodyId) {
    this.template = document.getElementById(templateId ?? 'container-panel-template');
    this.body = document.getElementById(bodyId ?? 'panels-container');
  }

  render(containers) {
    this.body.innerHTML = '';

    if (!containers.length) {
      this.body.innerHTML = `<div class="text-center py-8 text-gray-500" style="grid-column:1/-1">No containers found matching your criteria.</div>`;
      return;
    }

    const hasAnyTraefikRoutes = window.traefikEnabled !== false &&
      containers.some(c => c.traefik_routes?.length);

    const fragment = document.createDocumentFragment();

    if (state.groupByStack) {
      this._renderGrouped(containers, hasAnyTraefikRoutes, fragment);
    } else {
      for (const container of containers) {
        fragment.appendChild(this._renderPanel(container, hasAnyTraefikRoutes));
      }
    }

    this.body.appendChild(fragment);
  }

  _renderPanel(container, _hasAnyTraefikRoutes) {
    const clone = this.template.content.cloneNode(true);
    const panel = clone.querySelector('.container-panel');

    // Running state class for CSS orange accent
    const status = (container.Status || container.status || '').toLowerCase();
    const isRunning = status === 'running' || status === 'healthy';
    if (isRunning) panel.classList.add('is-running');

    // Container name
    const nameEl = clone.querySelector('[data-content="container-name"]');
    if (nameEl) nameEl.textContent = container.name || container.Names || '—';

    // Image name (trim tag)
    const imageEl = clone.querySelector('[data-content="image-name"]');
    const rawImage = container.image || container.Image || '';
    if (imageEl) {
      imageEl.textContent = rawImage.split(':')[0] || rawImage;
    }

    // Panel icon — try Dashboard Icons CDN, fallback to generic SVG
    const iconEl = clone.querySelector('[data-content="panel-icon"]');
    if (iconEl) {
      const iconName = _resolveIconName(rawImage, container.name || '');
      const fallbackSvg = `<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" opacity="0.4">
        <rect x="2" y="2" width="20" height="20" rx="5"/><path d="M8 12h8M12 8v8"/>
      </svg>`;
      if (iconName) {
        const img = document.createElement('img');
        img.src = `https://cdn.jsdelivr.net/gh/walkxcode/dashboard-icons@main/png/${iconName}.png`;
        img.width = 28;
        img.height = 28;
        img.style.cssText = 'border-radius:6px;object-fit:contain;';
        img.onerror = () => { iconEl.innerHTML = fallbackSvg; };
        iconEl.innerHTML = '';
        iconEl.appendChild(img);
      } else {
        iconEl.innerHTML = fallbackSvg;
      }
    }

    // Logs button wiring
    const gearBtn = clone.querySelector('[data-content="logs-trigger"]');
    if (gearBtn) {
      gearBtn.dataset.container = container.name || '';
      gearBtn.dataset.server = container.server || '';
    }

    // Running badge in header
    const runningBadgeEl = clone.querySelector('[data-content="running-badge"]');
    if (runningBadgeEl && isRunning) {
      runningBadgeEl.className = 'panel-running-badge panel-running-badge--active';
      runningBadgeEl.innerHTML = '<span class="panel-running-dot"></span>Running';
    }

    // Port badges in Name column (host port numbers)
    const portBadgesEl = clone.querySelector('[data-content="port-badges"]');
    if (portBadgesEl) {
      const ports = container.ports || container.Ports || [];
      if (Array.isArray(ports) && ports.length > 0) {
        portBadgesEl.innerHTML = ports.slice(0, 4).map(p => {
          const hostPort = p.PublicPort || p.host_port || p.hostPort || '';
          return hostPort ? `<span class="badge" style="display:inline-block;margin-bottom:2px;margin-right:2px">${escapeHtml(String(hostPort))}</span>` : '';
        }).join('');
      } else {
        portBadgesEl.textContent = '—';
      }
    }

    // Stack column value (port/protocol mapping lines)
    const stackValueEl = clone.querySelector('[data-content="stack-value"]');
    if (stackValueEl) {
      const ports = container.ports || container.Ports || [];
      if (Array.isArray(ports) && ports.length > 0) {
        stackValueEl.innerHTML = ports.slice(0, 4).map(p => {
          const containerPort = p.container_port || p.containerPort || '';
          const displayPort = containerPort || (p.PrivatePort ? `${p.PrivatePort}/${p.Type || 'tcp'}` : '');
          return displayPort ? `<div style="font-size:11px;opacity:0.7">›${escapeHtml(displayPort)}</div>` : '';
        }).join('');
      } else {
        stackValueEl.textContent = container.stack || '—';
      }
    }

    // Ports count
    const portsCountEl = clone.querySelector('[data-content="ports-count"]');
    if (portsCountEl) {
      const ports = container.ports || container.Ports || [];
      portsCountEl.textContent = ports.length > 0 ? String(ports.length) : '—';
    }

    // Status text
    const statusTextEl = clone.querySelector('[data-content="status-text"]');
    if (statusTextEl) {
      statusTextEl.textContent = container.Status || container.status || 'unknown';
    }

    // Status dot color class
    const dotEl = clone.querySelector('.panel-status-dot');
    if (dotEl) {
      dotEl.classList.add(`status-dot-${status}`);
    }

    // CVE display in status box — traffic lights, clean shield, or pending
    const cveEl = clone.querySelector('[data-content="cve-status"]');
    if (cveEl) {
      const v = container.vulnerability_summary;
      const scanStatus = v?.scan_status;

      if (scanStatus === 'scanned') {
        const total = (v.critical || 0) + (v.high || 0) + (v.medium || 0) + (v.low || 0);
        if (total === 0) {
          panel.classList.add('cve-clean');
          cveEl.innerHTML = `
            <div class="cve-clean-icon">
              <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                <polyline points="9 12 11 14 15 10"/>
              </svg>
            </div>
            <div class="cve-clean-label">Clean</div>`;
        } else {
          const rows = [];
          if (v.critical > 0) rows.push(`<div class="cve-row cve-row-critical"><span class="cve-pip cve-pip-critical"></span><span>${v.critical}</span><span class="cve-row-label">Crit</span></div>`);
          if (v.high     > 0) rows.push(`<div class="cve-row cve-row-high"><span class="cve-pip cve-pip-high"></span><span>${v.high}</span><span class="cve-row-label">High</span></div>`);
          if (v.medium   > 0) rows.push(`<div class="cve-row cve-row-medium"><span class="cve-pip cve-pip-medium"></span><span>${v.medium}</span><span class="cve-row-label">Med</span></div>`);
          if (v.low      > 0) rows.push(`<div class="cve-row cve-row-low"><span class="cve-pip cve-pip-low"></span><span>${v.low}</span><span class="cve-row-label">Low</span></div>`);
          cveEl.innerHTML = `<div class="cve-rows">${rows.join('')}</div>`;
          if (v.critical > 0)      panel.classList.add('cve-sev-critical');
          else if (v.high > 0)     panel.classList.add('cve-sev-high');
          else if (v.medium > 0)   panel.classList.add('cve-sev-medium');
          else                     panel.classList.add('cve-sev-low');
        }
      }
      // not_scanned / skipped / failed / error / null — leave box empty
    }

    // Update badge — show only when truly available (bypass hidden class specificity issue)
    const updateBadgeEl = clone.querySelector('[data-content="update-indicator"]');
    if (updateBadgeEl) {
      if (container.update_available) {
        updateBadgeEl.style.display = '';
        updateBadgeEl.classList.add('update-available-indicator');
        updateBadgeEl.setAttribute('data-server', container.server || '');
        updateBadgeEl.setAttribute('data-container', container.name || '');
        updateBadgeEl.setAttribute('data-tooltip', `Click to update ${container.name}`);
      } else {
        updateBadgeEl.style.display = 'none';
      }
    }

    // Registry link — show only when URL resolves
    const registryLinkEl = clone.querySelector('[data-content="registry-link"]');
    if (registryLinkEl) {
      const url = getRegistryUrl(container.image || container.Image || '');
      if (url) {
        registryLinkEl.href = url;
        registryLinkEl.style.display = '';
      } else {
        registryLinkEl.style.display = 'none';
      }
    }

    return clone;
  }

  _renderGrouped(containers, hasAnyTraefikRoutes, fragment) {
    const groups = new Map();
    const noStack = [];

    for (const container of containers) {
      const stackName = container.stack?.trim() || '';
      if (stackName) {
        if (!groups.has(stackName)) groups.set(stackName, []);
        groups.get(stackName).push(container);
      } else {
        noStack.push(container);
      }
    }

    const sortedNames = [...groups.keys()].sort((a, b) =>
      a.toLowerCase().localeCompare(b.toLowerCase())
    );

    for (const stackName of sortedNames) {
      const isCollapsed = this._isGroupCollapsed(stackName);
      fragment.appendChild(this._renderGroupHeader(stackName, groups.get(stackName).length, isCollapsed));
      if (!isCollapsed) {
        for (const container of groups.get(stackName)) {
          fragment.appendChild(this._renderPanel(container, hasAnyTraefikRoutes));
        }
      }
    }

    if (noStack.length > 0) {
      const isCollapsed = this._isGroupCollapsed('__ungrouped__');
      fragment.appendChild(this._renderGroupHeader('(ungrouped)', noStack.length, isCollapsed));
      if (!isCollapsed) {
        for (const container of noStack) {
          fragment.appendChild(this._renderPanel(container, hasAnyTraefikRoutes));
        }
      }
    }
  }

  _isGroupCollapsed(stackName) {
    try {
      const saved = JSON.parse(localStorage.getItem('collapsedStacks') || '{}');
      return saved[stackName] === true;
    } catch {
      return false;
    }
  }

  _renderGroupHeader(stackName, count, isCollapsed) {
    const div = document.createElement('div');
    div.className = 'stack-group-header';
    div.dataset.stack = stackName;
    div.style.cssText = 'grid-column: 1 / -1;';

    const cell = document.createElement('div');
    cell.className = 'stack-group-header-cell';
    cell.innerHTML = `
      <button class="stack-group-toggle" aria-expanded="${!isCollapsed}">
        <svg class="stack-group-chevron${isCollapsed ? ' collapsed' : ''}" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
          <polyline points="6 9 12 15 18 9"></polyline>
        </svg>
        <span class="stack-group-name">${escapeHtml(stackName)}</span>
        <span class="stack-group-count">${count}</span>
      </button>
    `;

    div.appendChild(cell);
    return div;
  }
}

/**
 * Resolve a dashboard-icons slug from an image name + container name.
 * Returns a slug string (may still 404 if icon doesn't exist — onerror handles that).
 */
function _resolveIconName(imageName, containerName) {
  const withoutTag = imageName.split(':')[0];
  const parts = withoutTag.split('/');
  let slug = parts[parts.length - 1] || '';

  if (!slug || ['app', 'server', 'backend', 'frontend'].includes(slug)) {
    slug = containerName;
  }

  slug = slug.toLowerCase().replace(/_/g, '-');

  const remaps = {
    'alertmanager':   'alertmanager',
    'prometheus':     'prometheus',
    'grafana':        'grafana',
    'loki':           'loki',
    'promtail':       'promtail',
    'cadvisor':       'cadvisor',
    'portainer':      'portainer',
    'traefik':        'traefik',
    'crowdsec':       'crowdsec',
    'authelia':       'authelia',
    'vaultwarden':    'vaultwarden',
    'vault':          'vault',
    'sonarr':         'sonarr',
    'radarr':         'radarr',
    'bazarr':         'bazarr',
    'prowlarr':       'prowlarr',
    'lidarr':         'lidarr',
    'readarr':        'readarr',
    'overseerr':      'overseerr',
    'jellyfin':       'jellyfin',
    'plex':           'plex',
    'emby':           'emby',
    'navidrome':      'navidrome',
    'nextcloud':      'nextcloud',
    'nginx':          'nginx',
    'unifi':          'unifi',
    'homeassistant':  'home-assistant',
    'home-assistant': 'home-assistant',
    'mosquitto':      'mosquitto',
    'node-red':       'node-red',
    'redis':          'redis',
    'postgres':       'postgresql',
    'postgresql':     'postgresql',
    'mariadb':        'mariadb',
    'mysql':          'mysql',
    'mongodb':        'mongodb',
    'influxdb':       'influxdb',
    'diun':           'diun',
    'watchtower':     'watchtower',
    'uptime-kuma':    'uptime-kuma',
    'heimdall':       'heimdall',
    'homer':          'homer',
    'duplicati':      'duplicati',
    'gitea':          'gitea',
    'gitlab':         'gitlab',
    'syncthing':      'syncthing',
    'cloudflared':    'cloudflare',
    'pihole':         'pi-hole',
    'adguard':        'adguard-home',
    'paperless':      'paperless-ngx',
    'mealie':         'mealie',
    'immich':         'immich',
    'kavita':         'kavita',
    'jackett':        'jackett',
    'qbittorrent':    'qbittorrent',
    'transmission':   'transmission',
    'deluge':         'deluge',
    'sabnzbd':        'sabnzbd',
    'wazuh':          'wazuh',
  };

  return remaps[slug] ?? slug;
}
