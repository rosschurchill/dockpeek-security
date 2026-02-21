/**
 * Security Dashboard Summary Panel
 * Displays aggregate vulnerability counts across all containers with trend indicators.
 */

import { escapeHtml } from './utils/sanitize.js';

const API_PREFIX = document.querySelector('meta[name="api-prefix"]')?.content || '';

/**
 * Calculate security summary from container data.
 */
export function calculateSecuritySummary(containers) {
  const summary = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    total: 0,
    scanned: 0,
    unscanned: 0,
    new_count: 0,
    improving: 0,
    degrading: 0,
    stable: 0
  };

  if (!containers || !Array.isArray(containers)) {
    return summary;
  }

  for (const container of containers) {
    const vuln = container.vulnerability_summary;
    if (!vuln) {
      summary.unscanned++;
      continue;
    }

    if (vuln.scan_status === 'scanned') {
      summary.scanned++;
      summary.critical += vuln.critical || 0;
      summary.high += vuln.high || 0;
      summary.medium += vuln.medium || 0;
      summary.low += vuln.low || 0;
      summary.new_count += vuln.new_count || 0;

      // Count trends
      if (vuln.trend === 'improving') summary.improving++;
      else if (vuln.trend === 'degrading') summary.degrading++;
      else if (vuln.trend === 'stable') summary.stable++;
    } else if (vuln.scan_status === 'not_scanned') {
      summary.unscanned++;
    }
  }

  summary.total = summary.critical + summary.high + summary.medium + summary.low;

  return summary;
}

/**
 * Determine overall trend direction.
 */
function getOverallTrend(summary) {
  if (summary.degrading > summary.improving) {
    return { icon: '↑', class: 'trend-degrading', label: 'Degrading' };
  } else if (summary.improving > summary.degrading) {
    return { icon: '↓', class: 'trend-improving', label: 'Improving' };
  } else if (summary.stable > 0) {
    return { icon: '→', class: 'trend-stable', label: 'Stable' };
  }
  return { icon: '-', class: 'trend-unknown', label: 'Unknown' };
}

// SVG icons for security stats (matching container-stats style)
const securityIcons = {
  shield: '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path></svg>',
  critical: '<svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-2 15l-5-5 1.41-1.41L10 14.17l7.59-7.59L19 8l-9 9z"/></svg>',
  high: '<svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor"><path d="M1 21h22L12 2 1 21zm12-3h-2v-2h2v2zm0-4h-2v-4h2v4z"/></svg>',
  medium: '<svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm1 15h-2v-2h2v2zm0-4h-2V7h2v6z"/></svg>',
  low: '<svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm1 15h-2v-6h2v6zm0-8h-2V7h2v2z"/></svg>',
  scan: '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/></svg>'
};

/**
 * Render the security dashboard HTML - unified pill style matching container stats.
 */
export function renderSecurityDashboard(containers) {
  const summary = calculateSecuritySummary(containers);

  // Build stats array - same format as container stats
  const stats = [];

  if (summary.critical > 0) {
    stats.push(`<span class="stat-item stat-critical" data-tooltip="Critical vulnerabilities">${securityIcons.critical}${summary.critical}</span>`);
  }
  if (summary.high > 0) {
    stats.push(`<span class="stat-item stat-high" data-tooltip="High severity">${securityIcons.high}${summary.high}</span>`);
  }
  if (summary.medium > 0) {
    stats.push(`<span class="stat-item stat-medium" data-tooltip="Medium severity">${securityIcons.medium}${summary.medium}</span>`);
  }
  if (summary.low > 0) {
    stats.push(`<span class="stat-item stat-low" data-tooltip="Low severity">${securityIcons.low}${summary.low}</span>`);
  }
  if (summary.scanned > 0 || summary.unscanned > 0) {
    stats.push(`<span class="stat-item stat-scanned" data-tooltip="Scanned containers">${securityIcons.scan}${summary.scanned}/${summary.scanned + summary.unscanned}</span>`);
  }

  if (stats.length === 0) {
    return '';
  }

  return `<div class="security-stats">${stats.join('')}</div>`;
}

/**
 * Initialize the security dashboard.
 */
export function initSecurityDashboard() {
  // Toggle collapse state
  document.addEventListener('click', (e) => {
    if (e.target.closest('#security-dashboard-toggle')) {
      const dashboard = document.getElementById('security-dashboard');
      if (dashboard) {
        dashboard.classList.toggle('collapsed');
        const isCollapsed = dashboard.classList.contains('collapsed');
        localStorage.setItem('securityDashboardCollapsed', isCollapsed);

        // Update toggle icon
        const toggle = document.getElementById('security-dashboard-toggle');
        if (toggle) {
          toggle.innerHTML = `
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <polyline points="${isCollapsed ? '6 9 12 15 18 9' : '18 15 12 9 6 15'}"></polyline>
            </svg>
          `;
        }
      }
    }
  });
}

/**
 * Update the security dashboard with new data.
 */
export function updateSecurityDashboard(containers) {
  const container = document.getElementById('security-dashboard-container');
  if (container) {
    container.innerHTML = renderSecurityDashboard(containers);
  }
}
