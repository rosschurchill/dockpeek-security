import { state } from './state.js';
import { getRegistryUrl } from './registry-urls.js';
import { escapeHtml, escapeAttr, sanitizeUrl, validateHttpUrl } from './utils/sanitize.js';

export function renderName(container, cell) {
  const nameSpan = cell.querySelector('[data-content="container-name"]');

  if (container.custom_url) {
    const url = validateHttpUrl(container.custom_url);
    if (url) {
      const tooltipUrl = url.replace(/^https?:\/\//, '');
      nameSpan.innerHTML = `<a href="${escapeAttr(url)}" target="_blank" rel="noopener noreferrer" class="text-blue-600 hover:text-blue-800" data-tooltip="${escapeAttr(tooltipUrl)}">${escapeHtml(container.name)}</a>`;
    } else {
      nameSpan.textContent = container.name;
    }
  } else {
    nameSpan.textContent = container.name;
  }
}

export function renderServer(container, clone) {
  const serverCell = clone.querySelector('[data-content="server-name"]').closest('td');
  const serverSpan = serverCell.querySelector('[data-content="server-name"]');
  serverSpan.textContent = container.server;

  const serverData = state.allContainersData.find(s => s.name === container.server);
  if (serverData?.url) {
    serverSpan.setAttribute('data-tooltip', serverData.url);
  }
}

export function renderStack(container, cell) {
  if (container.stack) {
    cell.innerHTML = `<a href="#" class="stack-link text-blue-600 hover:text-blue-800 cursor-pointer" data-stack="${escapeAttr(container.stack)}" data-server="${escapeAttr(container.server)}">${escapeHtml(container.stack)}</a>`;
  } else {
    cell.textContent = '';
  }
}

export function renderImage(container, cell, clone) {
  cell.innerHTML = `<span class="image-name" data-tooltip="${escapeAttr(container.image)}">${escapeHtml(container.image)}</span>`;

  const sourceLink = clone.querySelector('[data-content="source-link"]');
  if (sourceLink) {
    if (container.source_url) {
      sourceLink.href = container.source_url;
      sourceLink.classList.remove('hidden');
      sourceLink.setAttribute('data-tooltip', container.source_url);
    } else {
      sourceLink.classList.add('hidden');
    }
  }

  const registryLink = clone.querySelector('[data-content="registry-link"]');
  if (registryLink) {
    const registryUrl = getRegistryUrl(container.image);
    if (registryUrl) {
      registryLink.href = registryUrl;
      registryLink.classList.remove('hidden');
      registryLink.setAttribute('data-tooltip', 'Open in registry');
    } else {
      registryLink.classList.add('hidden');
    }
  }
}

export function renderUpdateIndicator(container, clone) {
  const indicator = clone.querySelector('[data-content="update-indicator"]');

  if (container.update_available) {
    indicator.classList.remove('hidden');
    indicator.classList.add('update-available-indicator');
    indicator.setAttribute('data-server', container.server);
    indicator.setAttribute('data-container', container.name);
    indicator.setAttribute('data-tooltip', `Click to update ${container.name}`);
    indicator.style.cursor = 'pointer';
  } else {
    indicator.classList.add('hidden');
    indicator.classList.remove('update-available-indicator');
    indicator.removeAttribute('data-server');
    indicator.removeAttribute('data-container');
    indicator.removeAttribute('data-tooltip');
    indicator.style.cursor = '';
  }
}

export function renderNewVersionIndicator(container, clone) {
  const indicator = clone.querySelector('[data-content="new-version-indicator"]');
  if (!indicator) return;

  if (container.newer_version_available && container.latest_version) {
    indicator.classList.remove('hidden');
    indicator.setAttribute('data-server', container.server);
    indicator.setAttribute('data-container', container.name);
    indicator.setAttribute('data-image', container.image);
    indicator.setAttribute('data-latest-version', container.latest_version);
    indicator.setAttribute('data-tooltip', `New version: ${container.latest_version} (click to update)`);
    indicator.style.cursor = 'pointer';

    // Make the image clickable for version selection
    const imageCode = clone.querySelector('[data-content="image"]');
    if (imageCode) {
      imageCode.setAttribute('data-has-new-version', 'true');
      imageCode.setAttribute('data-server', container.server);
      imageCode.setAttribute('data-container', container.name);
      imageCode.setAttribute('data-image', container.image);
      imageCode.style.cursor = 'pointer';
      imageCode.setAttribute('data-tooltip', 'Click to select version');
    }
  } else {
    indicator.classList.add('hidden');
    indicator.removeAttribute('data-server');
    indicator.removeAttribute('data-container');
    indicator.removeAttribute('data-image');
    indicator.removeAttribute('data-latest-version');
    indicator.removeAttribute('data-tooltip');
    indicator.style.cursor = '';

    // Remove clickable state from image
    const imageCode = clone.querySelector('[data-content="image"]');
    if (imageCode) {
      imageCode.removeAttribute('data-has-new-version');
      imageCode.removeAttribute('data-server');
      imageCode.removeAttribute('data-container');
      imageCode.removeAttribute('data-image');
      imageCode.style.cursor = '';
      imageCode.removeAttribute('data-tooltip');
    }
  }
}

export function renderTags(container, cell) {
  if (container.tags?.length) {
    const sortedTags = [...container.tags].sort((a, b) =>
      a.toLowerCase().localeCompare(b.toLowerCase())
    );
    cell.innerHTML = `<div class="tags-container">${sortedTags.map(tag =>
      `<span class="tag-badge" data-tag="${escapeAttr(tag)}">${escapeHtml(tag)}</span>`
    ).join('')}</div>`;
  } else {
    cell.innerHTML = '';
  }
}

export function renderPorts(container, cell) {
  if (!container.ports.length) {
    cell.innerHTML = `<span class="status-none" style="padding-left: 5px;">none</span>`;
    return;
  }

  const arrowSvg = `<svg width="12" height="12" viewBox="0 0 48 48" xmlns="http://www.w3.org/2000/svg" class="align-middle"><path d="M19 12L31 24L19 36" stroke="currentColor" fill="none" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/></svg>`;

  const globalGroupingEnabled = window.portRangeGroupingEnabled !== false;
  const containerGroupingEnabled = container.port_range_grouping !== false;
  const shouldGroupPorts = globalGroupingEnabled && containerGroupingEnabled;

  if (shouldGroupPorts) {
    const portGroups = groupPortsIntoRanges(container.ports, window.portRangeThreshold || 5);

    cell.innerHTML = portGroups.map(group => {
      if (group.isRange) {
        const safeLink = validateHttpUrl(group.startPort.link);
        const rangeBadge = safeLink
          ? `<a href="${escapeAttr(safeLink)}" data-tooltip="${escapeAttr(safeLink)}" target="_blank" rel="noopener noreferrer" class="badge text-bg-dark rounded">${escapeHtml(group.startPort.host_port)}-${escapeHtml(group.endPort.host_port)}</a>`
          : `<span class="badge text-bg-dark rounded">${escapeHtml(group.startPort.host_port)}-${escapeHtml(group.endPort.host_port)}</span>`;

        if (group.startPort.is_custom || !group.startPort.container_port) {
          return `<div class="custom-port flex items-center mb-1">${rangeBadge}</div>`;
        }

        const startContainerPort = escapeHtml(group.startPort.container_port.split('/')[0]);
        const endContainerPort = escapeHtml(group.endPort.container_port.split('/')[0]);
        const protocol = escapeHtml(group.startPort.container_port.split('/')[1] || 'tcp');
        return `<div class="flex items-center mb-1">${rangeBadge}${arrowSvg}<small class="text-secondary">${startContainerPort}-${endContainerPort}/${protocol}</small></div>`;
      } else {
        const safeLink = validateHttpUrl(group.port.link);
        const badge = safeLink
          ? `<a href="${escapeAttr(safeLink)}" data-tooltip="${escapeAttr(safeLink)}" target="_blank" rel="noopener noreferrer" class="badge text-bg-dark rounded">${escapeHtml(group.port.host_port)}</a>`
          : `<span class="badge text-bg-dark rounded">${escapeHtml(group.port.host_port)}</span>`;

        if (group.port.is_custom || !group.port.container_port) {
          return `<div class="custom-port flex items-center mb-1">${badge}</div>`;
        }

        return `<div class="flex items-center mb-1">${badge}${arrowSvg}<small class="text-secondary">${escapeHtml(group.port.container_port)}</small></div>`;
      }
    }).join('');
  } else {
    cell.innerHTML = container.ports.map(p => {
      const safeLink = validateHttpUrl(p.link);
      const badge = safeLink
        ? `<a href="${escapeAttr(safeLink)}" data-tooltip="${escapeAttr(safeLink)}" target="_blank" rel="noopener noreferrer" class="badge text-bg-dark rounded">${escapeHtml(p.host_port)}</a>`
        : `<span class="badge text-bg-dark rounded">${escapeHtml(p.host_port)}</span>`;

      if (p.is_custom || !p.container_port) {
        return `<div class="custom-port flex items-center mb-1">${badge}</div>`;
      }

      return `<div class="flex items-center mb-1">${badge}${arrowSvg}<small class="text-secondary">${escapeHtml(p.container_port)}</small></div>`;
    }).join('');
  }
}

function groupPortsIntoRanges(ports, threshold = 5) {
  if (!ports.length) return [];

  const sortedPorts = [...ports].sort((a, b) => {
    const portA = parseInt(a.host_port, 10);
    const portB = parseInt(b.host_port, 10);
    if (portA !== portB) return portA - portB;
    
    const protocolA = a.container_port?.split('/')[1] || 'tcp';
    const protocolB = b.container_port?.split('/')[1] || 'tcp';
    if (protocolA === 'tcp' && protocolB === 'udp') return -1;
    if (protocolA === 'udp' && protocolB === 'tcp') return 1;
    return protocolA.localeCompare(protocolB);
  });

  const portsByProtocol = {};
  sortedPorts.forEach(port => {
    const protocol = port.container_port?.split('/')[1] || 'tcp';
    if (!portsByProtocol[protocol]) {
      portsByProtocol[protocol] = [];
    }
    portsByProtocol[protocol].push(port);
  });

  const groupsByProtocol = {};

  Object.keys(portsByProtocol).forEach(protocol => {
    const protocolPorts = portsByProtocol[protocol];
    const groups = [];

    let currentRange = null;

    for (let i = 0; i < protocolPorts.length; i++) {
      const port = protocolPorts[i];
      const portNum = parseInt(port.host_port, 10);
      
      if (currentRange && 
          portNum === currentRange.endPortNum + 1 &&
          port.is_custom === currentRange.startPort.is_custom) {
        currentRange.endPort = port;
        currentRange.endPortNum = portNum;
      } else {
        if (currentRange && (currentRange.endPortNum - currentRange.startPortNum + 1) >= threshold) {
          groups.push({
            isRange: true,
            startPort: currentRange.startPort,
            endPort: currentRange.endPort,
            startPortNum: currentRange.startPortNum,
            endPortNum: currentRange.endPortNum
          });
        } else if (currentRange) {
          for (let j = currentRange.startPortNum; j <= currentRange.endPortNum; j++) {
            const portToAdd = protocolPorts.find(p => parseInt(p.host_port, 10) === j);
            if (portToAdd) {
              groups.push({
                isRange: false,
                port: portToAdd
              });
            }
          }
        }
        
        currentRange = {
          startPort: port,
          endPort: port,
          startPortNum: portNum,
          endPortNum: portNum
        };
      }
    }

    if (currentRange) {
      if ((currentRange.endPortNum - currentRange.startPortNum + 1) >= threshold) {
        groups.push({
          isRange: true,
          startPort: currentRange.startPort,
          endPort: currentRange.endPort,
          startPortNum: currentRange.startPortNum,
          endPortNum: currentRange.endPortNum
        });
      } else {
        for (let j = currentRange.startPortNum; j <= currentRange.endPortNum; j++) {
          const portToAdd = protocolPorts.find(p => parseInt(p.host_port, 10) === j);
          if (portToAdd) {
            groups.push({
              isRange: false,
              port: portToAdd
            });
          }
        }
      }
    }

    groupsByProtocol[protocol] = groups;
  });

  const allGroups = [];
  sortedPorts.forEach(port => {
    const protocol = port.container_port?.split('/')[1] || 'tcp';
    const protocolGroups = groupsByProtocol[protocol];
    
    const group = protocolGroups.find(g => {
      if (g.isRange) {
        const portNum = parseInt(port.host_port, 10);
        return portNum >= g.startPortNum && portNum <= g.endPortNum;
      } else {
        return g.port === port;
      }
    });
    
    if (group && !allGroups.includes(group)) {
      allGroups.push(group);
    }
  });

  return allGroups;
}

export function renderTraefik(container, cell, hasAnyRoutes) {
  if (!hasAnyRoutes) {
    cell.classList.add('hidden');
    return;
  }

  cell.classList.remove('hidden');

  if (container.traefik_routes?.length) {
    cell.innerHTML = container.traefik_routes.map(route => {
      const safeUrl = validateHttpUrl(route.url);
      if (!safeUrl) return '';
      const displayUrl = safeUrl.replace(/^https?:\/\//, '');
      return `<div class="traefik-route mb-1"><div class="inline-block"><a href="${escapeAttr(safeUrl)}" target="_blank" rel="noopener noreferrer" class="text-blue-600 hover:text-blue-800 text-sm"><span class="traefik-text">${escapeHtml(displayUrl)}</span></a></div></div>`;
    }).join('');
  } else {
    cell.innerHTML = `<span class="status-none text-sm">none</span>`;
  }
}

function normalizeUrl(url) {
  return url.match(/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//) ? url : `https://${url}`;
}

export function renderLogs(container, cell) {
  const logsButton = document.createElement('button');
  logsButton.className = 'logs-button text-gray-500 hover:text-blue-600 p-1 rounded transition-colors';
  logsButton.setAttribute('data-server', container.server);
  logsButton.setAttribute('data-container', container.name);

  const tooltipText = container.name.length > 50
    ? container.name.substring(0, 47) + '...'
    : container.name;
  logsButton.setAttribute('data-tooltip', tooltipText);

  logsButton.setAttribute('aria-label', 'View container logs');
  logsButton.innerHTML = `
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1">
      <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path>
      <polyline points="14 2 14 8 20 8"></polyline>
      <line x1="16" y1="13" x2="8" y2="13"></line>
      <line x1="16" y1="17" x2="8" y2="17"></line>
      <polyline points="10 9 9 9 8 9"></polyline>
    </svg>
  `;
  cell.appendChild(logsButton);
}

export function renderNetworks(container, cell) {
  if (!container.networks || container.networks.length === 0) {
    cell.innerHTML = '<span class="status-none">--</span>';
    return;
  }

  cell.innerHTML = container.networks.map(network =>
    `<span class="network-badge" data-network="${escapeAttr(network)}" data-server="${escapeAttr(container.server)}">${escapeHtml(network)}</span>`
  ).join(' ');
}

export function renderIPAddresses(container, cell) {
  if (!container.ip_addresses || Object.keys(container.ip_addresses).length === 0) {
    cell.innerHTML = '<span class="status-none">--</span>';
    return;
  }

  const entries = Object.entries(container.ip_addresses);
  if (entries.length === 1) {
    cell.innerHTML = `<code class="ip-badge">${escapeHtml(entries[0][1])}</code>`;
  } else {
    cell.innerHTML = entries.map(([network, ip]) =>
      `<div class="ip-entry"><code class="ip-badge" data-tooltip="${escapeAttr(network)}">${escapeHtml(ip)}</code></div>`
    ).join('');
  }
}

export function renderSecurity(container, cell) {
  const vuln = container.vulnerability_summary;

  // Trivy not enabled or no data
  if (!vuln) {
    cell.innerHTML = '<span class="status-none">--</span>';
    return;
  }

  // Security scanning skipped for this container
  if (vuln.scan_status === 'skipped') {
    cell.innerHTML = '<span class="status-none" data-tooltip="Security scanning disabled">--</span>';
    return;
  }

  // Not yet scanned - show empty boxes with dashes
  if (vuln.scan_status === 'not_scanned') {
    cell.innerHTML = `
      <div class="vuln-summary" data-tooltip="Scanning...">
        <div class="vuln-traffic-light">
          <span class="vuln-badge vuln-zero">-</span>
          <span class="vuln-badge vuln-zero">-</span>
          <span class="vuln-badge vuln-zero">-</span>
          <span class="vuln-badge vuln-zero">-</span>
        </div>
      </div>
    `;
    return;
  }

  // Scan error
  if (vuln.scan_status === 'error') {
    cell.innerHTML = '<span class="status-none" data-tooltip="Scan error">Error</span>';
    return;
  }

  // Build Docker Hub style traffic light badges (C H M L)
  const c = vuln.critical || 0;
  const h = vuln.high || 0;
  const m = vuln.medium || 0;
  const l = vuln.low || 0;
  const total = c + h + m + l;

  const tooltip = total === 0
    ? 'No vulnerabilities found'
    : `${c} Critical, ${h} High, ${m} Medium, ${l} Low`;

  cell.innerHTML = `
    <div class="vuln-summary vuln-clickable" data-server="${escapeAttr(container.server)}" data-container="${escapeAttr(container.name)}" data-image="${escapeAttr(container.image)}" data-tooltip="${escapeAttr(tooltip)}">
      <div class="vuln-traffic-light">
        <span class="vuln-badge vuln-critical${c === 0 ? ' vuln-zero' : ''}" title="Critical">${c}</span>
        <span class="vuln-badge vuln-high${h === 0 ? ' vuln-zero' : ''}" title="High">${h}</span>
        <span class="vuln-badge vuln-medium${m === 0 ? ' vuln-zero' : ''}" title="Medium">${m}</span>
        <span class="vuln-badge vuln-low${l === 0 ? ' vuln-zero' : ''}" title="Low">${l}</span>
      </div>
    </div>
  `;
}

function formatRelativeTime(isoString) {
  try {
    const date = new Date(isoString);
    const now = new Date();
    const diffMs = now - date;
    const diffMins = Math.floor(diffMs / 60000);
    const diffHours = Math.floor(diffMins / 60);
    const diffDays = Math.floor(diffHours / 24);

    if (diffMins < 1) return 'now';
    if (diffMins < 60) return `${diffMins}m`;
    if (diffHours < 24) return `${diffHours}h`;
    return `${diffDays}d`;
  } catch {
    return '';
  }
}
