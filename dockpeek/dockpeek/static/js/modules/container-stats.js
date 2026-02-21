// modules/container-stats.js
import { state } from './state.js';

export function calculateStats(containers) {
  const stats = {
    running: 0,
    healthy: 0,
    unhealthy: 0,
    stopped: 0,
    paused: 0,
    other: 0,
    total: 0,
    stacks: 0
  };

  const stackNames = new Set();

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

    if (container.stack && container.stack.trim()) {
      stackNames.add(container.stack.trim());
    }
  });

  stats.stacks = stackNames.size;
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
  stacks: '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="12 2 2 7 12 12 22 7 12 2"/><polyline points="2 17 12 22 22 17"/><polyline points="2 12 12 17 22 12"/></svg>'
};

function pill(cls, filterKey, tooltip, icon, count) {
  const active = state.statusFilter === filterKey ? ' stat-active' : '';
  return `<button class="stat-item ${cls}${active}" data-filter="${filterKey}" data-tooltip="${tooltip}" type="button">${icon}${count}</button>`;
}

export function updateStatsDisplay(stats) {
  const container = document.getElementById('container-stats');
  if (!container) return;

  const items = [];

  if (stats.total > 0) {
    items.push(pill('stat-total', 'all', 'All containers', icons.total, stats.total));
  }
  if (stats.running > 0) {
    items.push(pill('stat-running', 'running', 'Running containers — click to filter', icons.running, stats.running));
  }
  if (stats.unhealthy > 0) {
    items.push(pill('stat-unhealthy', 'unhealthy', 'Unhealthy containers — click to filter', icons.unhealthy, stats.unhealthy));
  }
  if (stats.paused > 0) {
    items.push(pill('stat-paused', 'paused', 'Paused containers — click to filter', icons.paused, stats.paused));
  }
  if (stats.other > 0) {
    items.push(pill('stat-other', 'other', 'Other status — click to filter', icons.other, stats.other));
  }
  if (stats.stopped > 0) {
    items.push(pill('stat-stopped', 'stopped', 'Stopped containers — click to filter', icons.stopped, stats.stopped));
  }
  if (stats.stacks > 0) {
    items.push(pill('stat-stacks', 'stacked', `${stats.stacks} stacks — click to filter`, icons.stacks, stats.stacks));
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

let _refreshFn = null;

export function initStatsFilter(refreshFn) {
  _refreshFn = refreshFn;
  const statsContainer = document.getElementById('container-stats');
  if (!statsContainer) return;

  statsContainer.addEventListener('click', (e) => {
    const pill = e.target.closest('[data-filter]');
    if (!pill) return;
    const filter = pill.dataset.filter;
    // 'all' or same filter again → clear; otherwise set
    state.statusFilter = (filter === 'all' || state.statusFilter === filter) ? null : filter;
    _refreshFn();
  });
}
