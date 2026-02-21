import { apiUrl } from './config.js';
import { state } from './state.js';
import { showPruneInfoModal, showPruneResultModal } from './modals.js';

let isPruneInfoFetching = false;

export async function initPruneInfo() {
  try {
    if (state.pruneInfoCache && state.pruneInfoCache.server_name === 'all') {
      console.log('Using cached prune info');
      const serverData = state.pruneInfoCache.servers.find(s => s.server === state.currentServerFilter);
      const count = state.currentServerFilter === 'all'
        ? state.pruneInfoCache.total_count
        : (serverData ? serverData.count : 0);
      updatePruneBadge(count);
      return;
    }

    if (isPruneInfoFetching) {
      console.log('Prune info fetch already in progress, ignoring');
      return;
    }

    isPruneInfoFetching = true;

    updatePruneBadge('...');

    const response = await fetch(apiUrl('/get-prune-info'), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ server_name: 'all' })
    });

    if (response.ok) {
      const data = await response.json();
      state.pruneInfoCache = {
        server_name: 'all',
        total_count: data.total_count,
        total_size: data.total_size,
        servers: data.servers
      };

      const serverData = data.servers.find(s => s.server === state.currentServerFilter);
      const count = state.currentServerFilter === 'all'
        ? data.total_count
        : (serverData ? serverData.count : 0);
      updatePruneBadge(count);
    } else {
      updatePruneBadge(0);
    }
  } catch (error) {
    console.error('Error getting prune info:', error);
    updatePruneBadge(0);
  } finally {
    isPruneInfoFetching = false;
  }
}

export async function handlePruneImages() {
  if (isPruneInfoFetching) {
    console.log('Prune info fetch already in progress, ignoring');
    return;
  }

  try {
    isPruneInfoFetching = true;

    updatePruneBadge('...');

    const response = await fetch(apiUrl('/get-prune-info'), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ server_name: state.currentServerFilter })
    });

    if (!response.ok) throw new Error('Failed to get prune info');

    const data = await response.json();

    state.pruneInfoCache = {
      server_name: state.currentServerFilter,
      total_count: data.total_count,
      total_size: data.total_size,
      servers: data.servers
    };

    updatePruneBadge(data.total_count);

    try {
      await showPruneInfoModal(data);
      await performPrune();
    } catch (err) {
      console.log('Prune cancelled');
    }
  } catch (error) {
    console.error('Error getting prune info:', error);
    updatePruneBadge(0);
    alert('Failed to get image information. Please try again.');
  } finally {
    isPruneInfoFetching = false;
  }
}

async function performPrune() {
  try {
    const response = await fetch(apiUrl('/prune-images'), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ server_name: state.currentServerFilter })
    });

    if (!response.ok) throw new Error('Failed to prune images');

    const data = await response.json();
    showPruneResultModal(data);
    state.pruneInfoCache = null;
    updatePruneBadge(0);
  } catch (error) {
    console.error('Error pruning images:', error);
    alert('Failed to prune images. Please try again.');
  }
}

export function updatePruneBadge(count) {
  const badge = document.getElementById('prune-badge');
  if (count > 0) {
    badge.textContent = count;
    badge.classList.remove('hidden');
  } else {
    badge.classList.add('hidden');
  }
}