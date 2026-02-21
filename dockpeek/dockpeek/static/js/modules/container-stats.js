// modules/container-stats.js
export function calculateStats(containers) {
  const stats = {
    running: 0,
    healthy: 0,
    unhealthy: 0,
    stopped: 0,
    paused: 0,
    other: 0,
    total: 0
  };

  containers.forEach(container => {
    stats.total++;
    const status = container.status?.toLowerCase() || '';
    
    if (status === 'healthy') {
      stats.running++;
      stats.healthy++;
    } else if (status === 'unhealthy') {
      stats.unhealthy++;
    } else if (status === 'running' || status.startsWith('running (')) {
      stats.running++;
    } else if (status === 'exited' || status === 'dead') {
      stats.stopped++;
    } else if (status === 'paused') {
      stats.paused++;
    } else {
      stats.other++;
    }
  });

  return stats;
}

// All icons use viewBox="0 0 24 24" for consistent visual weight
const icons = {
  total: '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16"/><path d="M3.27 6.96 12 12.01l8.73-5.05M12 22.08V12"/></svg>',
  running: '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><polyline points="10 8 16 12 10 16 10 8"/></svg>',
  unhealthy: '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>',
  stopped: '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><rect x="9" y="9" width="6" height="6"/></svg>',
  paused: '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="10" y1="15" x2="10" y2="9"/><line x1="14" y1="15" x2="14" y2="9"/></svg>',
  other: '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>',
  healthy: '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><polyline points="9 12 11 14 15 10"/></svg>'
};

export function updateStatsDisplay(stats) {
  const container = document.getElementById('container-stats');
  if (!container) return;

  const items = [];
  
  if (stats.total > 0) {
    items.push(`<span class="stat-item stat-total" data-tooltip="Total containers">${icons.total}${stats.total}</span>`);
  }
  
  if (stats.running > 0) {
    let runningText = `${stats.running}`;
      /*
    if (stats.healthy > 0) {
      runningText += ` <span class="stat-detail" data-tooltip="Healthy containers">(${icons.healthy}${stats.healthy})</span>`;
    }
        */
    items.push(`<span class="stat-item stat-running" data-tooltip="Running containers">${icons.running}${runningText}</span>`);
  }
  
  if (stats.unhealthy > 0) {
    items.push(`<span class="stat-item stat-unhealthy" data-tooltip="Unhealthy containers">${icons.unhealthy}${stats.unhealthy}</span>`);
  }
  if (stats.paused > 0) {
    items.push(`<span class="stat-item stat-paused" data-tooltip="Paused containers">${icons.paused}${stats.paused}</span>`);
  }
  if (stats.other > 0) {
    items.push(`<span class="stat-item stat-other" data-tooltip="Other status containers">${icons.other}${stats.other}</span>`);
  }

  if (stats.stopped > 0) {
    items.push(`<span class="stat-item stat-stopped" data-tooltip="Stopped containers">${icons.stopped}${stats.stopped}</span>`);
  }

  const divider = document.getElementById('stats-divider');
  if (items.length > 0) {
    container.innerHTML = `<div class="container-stats">${items.join('')}</div>`;
    container.classList.remove('hidden');
    if (divider) divider.classList.remove('hidden');
  } else {
    container.innerHTML = '';
    container.classList.add('hidden');
    if (divider) divider.classList.add('hidden');
  }
}

export function updateContainerStats(containers) {
  const stats = calculateStats(containers);
  updateStatsDisplay(stats);
}