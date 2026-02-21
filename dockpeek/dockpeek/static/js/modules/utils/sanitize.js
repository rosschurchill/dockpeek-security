/**
 * Security utilities for XSS prevention.
 * All user-controlled data should be passed through these functions before DOM insertion.
 */

/**
 * Escape HTML special characters to prevent XSS.
 * Use this for any user-controlled string that will be inserted into innerHTML.
 * @param {string} str - The string to escape
 * @returns {string} - HTML-escaped string safe for innerHTML
 */
export function escapeHtml(str) {
  if (str === null || str === undefined) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

/**
 * Sanitize a URL to prevent JavaScript injection.
 * Blocks javascript:, data:, and vbscript: protocols.
 * @param {string} url - The URL to sanitize
 * @returns {string} - Safe URL or empty string if dangerous
 */
export function sanitizeUrl(url) {
  if (!url) return '';
  const trimmed = String(url).trim();
  const lower = trimmed.toLowerCase();

  // Block dangerous protocols
  if (lower.startsWith('javascript:') ||
      lower.startsWith('data:') ||
      lower.startsWith('vbscript:') ||
      lower.startsWith('file:')) {
    console.warn('Blocked dangerous URL protocol:', url);
    return '';
  }

  return trimmed;
}

/**
 * Validate and sanitize a URL, ensuring it uses http/https.
 * @param {string} url - The URL to validate
 * @returns {string} - Valid URL or empty string
 */
export function validateHttpUrl(url) {
  const sanitized = sanitizeUrl(url);
  if (!sanitized) return '';

  const lower = sanitized.toLowerCase();
  if (lower.startsWith('http://') || lower.startsWith('https://')) {
    return sanitized;
  }

  // Allow protocol-relative URLs
  if (lower.startsWith('//')) {
    return sanitized;
  }

  // Prepend https:// to bare URLs
  if (!lower.includes('://')) {
    return 'https://' + sanitized;
  }

  // Unknown protocol, reject
  return '';
}

/**
 * Escape a string for use in an HTML attribute.
 * @param {string} str - The string to escape
 * @returns {string} - Safe string for HTML attributes
 */
export function escapeAttr(str) {
  if (str === null || str === undefined) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

/**
 * Create a safe HTML link element.
 * @param {string} url - The URL (will be sanitized)
 * @param {string} text - The link text (will be escaped)
 * @param {object} options - Additional options
 * @returns {string} - Safe HTML anchor element
 */
export function safeLink(url, text, options = {}) {
  const safeUrl = validateHttpUrl(url);
  const safeText = escapeHtml(text || url);

  if (!safeUrl) {
    return `<span class="invalid-url">${safeText}</span>`;
  }

  const target = options.newTab !== false ? ' target="_blank" rel="noopener noreferrer"' : '';
  const className = options.className ? ` class="${escapeAttr(options.className)}"` : '';
  const tooltip = options.tooltip ? ` data-tooltip="${escapeAttr(options.tooltip)}"` : '';

  return `<a href="${escapeAttr(safeUrl)}"${target}${className}${tooltip}>${safeText}</a>`;
}
