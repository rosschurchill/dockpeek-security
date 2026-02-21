/**
 * Security Notifications - Bell icon with alerts for new critical CVEs.
 */

import { escapeHtml } from './utils/sanitize.js';

const API_PREFIX = document.querySelector('meta[name="api-prefix"]')?.content || '';

class SecurityNotifications {
  constructor() {
    this.lastCheckTimestamp = localStorage.getItem('lastSecurityCheck') || new Date(0).toISOString();
    this.unreadCount = 0;
    this.notifications = [];
    this.checkInterval = null;
    this.isDropdownOpen = false;
  }

  /**
   * Initialize the notification system.
   */
  init() {
    this.injectBellIcon();
    this.bindEvents();
    this.checkForNewCriticals();

    // Poll every 5 minutes
    this.checkInterval = setInterval(() => {
      this.checkForNewCriticals();
    }, 5 * 60 * 1000);
  }

  /**
   * Inject the bell icon into the header.
   */
  injectBellIcon() {
    const controlsContainer = document.querySelector('.controls-container');
    if (!controlsContainer) return;

    const bellContainer = document.createElement('div');
    bellContainer.id = 'security-bell-container';
    bellContainer.className = 'security-bell-container';
    bellContainer.innerHTML = `
      <button id="security-bell" class="security-bell" title="Security Notifications">
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"></path>
          <path d="M13.73 21a2 2 0 0 1-3.46 0"></path>
        </svg>
        <span id="security-bell-badge" class="bell-badge hidden">0</span>
      </button>
      <div id="security-bell-dropdown" class="security-bell-dropdown hidden">
        <div class="dropdown-header">
          <span>Security Alerts</span>
          <button id="mark-all-read" class="mark-all-read">Mark all read</button>
        </div>
        <div id="notification-list" class="notification-list">
          <div class="notification-empty">No new alerts</div>
        </div>
      </div>
    `;

    // Insert before the first control
    controlsContainer.insertBefore(bellContainer, controlsContainer.firstChild);
  }

  /**
   * Bind event listeners.
   */
  bindEvents() {
    // Toggle dropdown
    document.addEventListener('click', (e) => {
      const bell = e.target.closest('#security-bell');
      const dropdown = document.getElementById('security-bell-dropdown');

      if (bell) {
        e.stopPropagation();
        this.isDropdownOpen = !this.isDropdownOpen;
        dropdown?.classList.toggle('hidden', !this.isDropdownOpen);
      } else if (!e.target.closest('#security-bell-dropdown')) {
        this.isDropdownOpen = false;
        dropdown?.classList.add('hidden');
      }
    });

    // Mark all as read
    document.addEventListener('click', (e) => {
      if (e.target.closest('#mark-all-read')) {
        this.markAllRead();
      }
    });
  }

  /**
   * Check for new critical vulnerabilities.
   */
  async checkForNewCriticals() {
    try {
      const response = await fetch(
        `${API_PREFIX}/api/security/new-vulnerabilities?hours=24&severity=CRITICAL`
      );

      if (!response.ok) return;

      const data = await response.json();

      if (!data.vulnerabilities || data.vulnerabilities.length === 0) {
        this.updateBadge(0);
        return;
      }

      // Filter to only truly new ones since last check
      const lastCheck = new Date(this.lastCheckTimestamp);
      const newCriticals = data.vulnerabilities.filter(v => {
        const firstSeen = new Date(v.first_seen_at);
        return firstSeen > lastCheck;
      });

      if (newCriticals.length > 0) {
        this.notifications = newCriticals;
        this.unreadCount = newCriticals.length;
        this.updateBadge(this.unreadCount);
        this.updateDropdownList();
        this.showToast(`${newCriticals.length} new critical vulnerabilities detected!`);
      }

    } catch (error) {
      console.error('Failed to check for new vulnerabilities:', error);
    }
  }

  /**
   * Update the badge count.
   */
  updateBadge(count) {
    const badge = document.getElementById('security-bell-badge');
    if (!badge) return;

    this.unreadCount = count;
    badge.textContent = count > 99 ? '99+' : count;
    badge.classList.toggle('hidden', count === 0);

    // Add pulse animation for new alerts
    const bell = document.getElementById('security-bell');
    if (bell) {
      bell.classList.toggle('has-alerts', count > 0);
    }
  }

  /**
   * Update the dropdown notification list.
   */
  updateDropdownList() {
    const list = document.getElementById('notification-list');
    if (!list) return;

    if (this.notifications.length === 0) {
      list.innerHTML = '<div class="notification-empty">No new alerts</div>';
      return;
    }

    list.innerHTML = this.notifications.slice(0, 10).map(n => `
      <div class="notification-item">
        <div class="notification-severity">CRITICAL</div>
        <div class="notification-cve">${escapeHtml(n.cve_id)}</div>
        <div class="notification-time">${this.formatTime(n.first_seen_at)}</div>
      </div>
    `).join('');
  }

  /**
   * Format timestamp for display.
   */
  formatTime(isoString) {
    try {
      const date = new Date(isoString);
      const now = new Date();
      const diffMs = now - date;
      const diffMins = Math.floor(diffMs / 60000);
      const diffHours = Math.floor(diffMins / 60);

      if (diffMins < 1) return 'just now';
      if (diffMins < 60) return `${diffMins}m ago`;
      if (diffHours < 24) return `${diffHours}h ago`;
      return date.toLocaleDateString();
    } catch {
      return '';
    }
  }

  /**
   * Show a toast notification.
   */
  showToast(message) {
    // Check if toast container exists, create if not
    let toastContainer = document.getElementById('toast-container');
    if (!toastContainer) {
      toastContainer = document.createElement('div');
      toastContainer.id = 'toast-container';
      toastContainer.className = 'toast-container';
      document.body.appendChild(toastContainer);
    }

    const toast = document.createElement('div');
    toast.className = 'toast toast-critical';
    toast.innerHTML = `
      <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path>
        <line x1="12" y1="9" x2="12" y2="13"></line>
        <line x1="12" y1="17" x2="12.01" y2="17"></line>
      </svg>
      <span>${escapeHtml(message)}</span>
    `;

    toastContainer.appendChild(toast);

    // Auto-remove after 5 seconds
    setTimeout(() => {
      toast.classList.add('toast-fade-out');
      setTimeout(() => toast.remove(), 300);
    }, 5000);
  }

  /**
   * Mark all notifications as read.
   */
  markAllRead() {
    this.lastCheckTimestamp = new Date().toISOString();
    localStorage.setItem('lastSecurityCheck', this.lastCheckTimestamp);
    this.notifications = [];
    this.updateBadge(0);
    this.updateDropdownList();
  }

  /**
   * Cleanup on destroy.
   */
  destroy() {
    if (this.checkInterval) {
      clearInterval(this.checkInterval);
    }
  }
}

// Export singleton instance
export const securityNotifications = new SecurityNotifications();

// Initialize when DOM ready
export function initSecurityNotifications() {
  securityNotifications.init();
}
