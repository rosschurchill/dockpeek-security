
import { state } from './state.js';
/**
 * @param {Array} swarmServers
 * @param {string} currentServerFilter 
 */
export function isSwarmMode() {
  if (state.currentServerFilter === 'all') {
    return state.swarmServers && state.swarmServers.length > 0;
  } else {
    return state.swarmServers && state.swarmServers.includes(state.currentServerFilter);
  }
}

export function updateSwarmIndicator(swarmServers, currentServerFilter) {
  const indicator = document.getElementById('swarm-indicator');
  if (!indicator) return;
  
  const isSwarmActive = swarmServers && swarmServers.length > 0 && 
    (currentServerFilter === 'all' || swarmServers.includes(currentServerFilter));
  
  if (isSwarmActive) {
    indicator.classList.remove('hidden');
    if (swarmServers.length > 1) {
      indicator.setAttribute('data-tooltip', `Swarm servers: ${swarmServers.join(' • ')}`);
    } else {
      indicator.setAttribute('data-tooltip', `Server "${swarmServers[0]}" running in Swarm mode`);
    }
  } else {
    indicator.classList.add('hidden');
    indicator.removeAttribute('data-tooltip');
  }
}

export function initSwarmIndicator() {
  const logoContainer = document.querySelector('.flex.items-center.space-x-4');
  if (!logoContainer || document.getElementById('swarm-indicator')) return;
  
  const indicator = document.createElement('div');
  indicator.id = 'swarm-indicator';
  indicator.className = 'hidden flex items-center space-x-2 px-3 py-1 rounded-full text-sm font-medium swarm-indicator';
  
  indicator.innerHTML = `
    <svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor">
      <path d="M12 2L13.09 8.26L20 9L13.09 9.74L12 16L10.91 9.74L4 9L10.91 8.26L12 2M6.5 12.5L7.5 16.5L11.5 17.5L7.5 18.5L6.5 22.5L5.5 18.5L1.5 17.5L5.5 16.5L6.5 12.5M17.5 12.5L18.5 16.5L22.5 17.5L18.5 18.5L17.5 22.5L16.5 18.5L12.5 17.5L16.5 16.5L17.5 12.5Z"/>
    </svg>
    <span>Swarm Mode</span>
  `;
  
  logoContainer.appendChild(indicator);
}