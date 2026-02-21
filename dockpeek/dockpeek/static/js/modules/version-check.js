/**
 * Version checking module for detecting newer image versions.
 * Queries registries to find newer version tags available for pinned images.
 */

import { showConfirmationModal } from './modals.js';

const API_PREFIX = document.querySelector('meta[name="api-prefix"]')?.content || '';

// Cache for version check results (in-memory for session)
const versionCache = new Map();
const CACHE_TTL = 5 * 60 * 1000; // 5 minutes

/**
 * Check if a newer version is available for an image.
 * Results are cached to avoid repeated API calls.
 */
export async function checkImageVersion(image) {
  // Check cache first
  const cached = versionCache.get(image);
  if (cached && Date.now() - cached.timestamp < CACHE_TTL) {
    return cached.result;
  }

  try {
    const response = await fetch(`${API_PREFIX}/api/version/check/${encodeURIComponent(image)}`);
    const data = await response.json();

    // Cache the result
    versionCache.set(image, {
      result: data,
      timestamp: Date.now()
    });

    return data;
  } catch (error) {
    console.error(`Version check failed for ${image}:`, error);
    return null;
  }
}

/**
 * Get list of available versions for an image.
 */
export async function listImageVersions(image, limit = 20) {
  try {
    const response = await fetch(`${API_PREFIX}/api/version/list/${encodeURIComponent(image)}?limit=${limit}`);
    return await response.json();
  } catch (error) {
    console.error(`Failed to list versions for ${image}:`, error);
    return null;
  }
}

/**
 * Show version selection modal for an image.
 */
export async function showVersionModal(serverName, containerName, image) {
  const modal = document.getElementById('version-modal');
  const listEl = document.getElementById('version-list');
  const imageEl = document.getElementById('version-modal-image');
  const currentEl = document.getElementById('version-modal-current');

  if (!modal || !listEl) {
    console.error('Version modal elements not found');
    return;
  }

  // Show modal with loading state
  modal.classList.remove('hidden');
  imageEl.textContent = image.split(':')[0];
  currentEl.textContent = image.split(':')[1] || 'latest';
  listEl.innerHTML = '<div class="text-center text-gray-500 py-8">Loading versions...</div>';

  // Store container info for update action
  modal.dataset.serverName = serverName;
  modal.dataset.containerName = containerName;
  modal.dataset.currentImage = image;

  try {
    const data = await listImageVersions(image, 30);

    if (!data || data.error) {
      listEl.innerHTML = `
        <div class="text-center py-8 text-red-500">
          ${data?.error || 'Failed to fetch versions'}
        </div>
      `;
      return;
    }

    if (!data.versions || data.versions.length === 0) {
      listEl.innerHTML = `
        <div class="text-center py-8 text-gray-500">
          No versioned tags found
        </div>
      `;
      return;
    }

    // Render versions list
    const currentTag = image.split(':')[1] || 'latest';
    let html = '<div class="space-y-1">';

    for (const version of data.versions) {
      const isCurrent = version.tag === currentTag;
      const isNewer = version.is_newer;
      const isStable = version.is_stable !== false;  // default to stable if not specified

      // Different styling for stable vs dev versions
      let badgeClass;
      if (isCurrent) {
        badgeClass = 'bg-blue-100 text-blue-700';
      } else if (!isStable) {
        badgeClass = 'bg-yellow-50 text-yellow-700 opacity-75';
      } else if (isNewer) {
        badgeClass = 'bg-green-100 text-green-700';
      } else {
        badgeClass = 'bg-gray-100 text-gray-600';
      }

      // Build badges
      let badges = '';
      if (isCurrent) {
        badges += '<span class="text-xs bg-blue-500 text-white px-1.5 py-0.5 rounded ml-2">current</span>';
      } else if (isNewer && isStable) {
        badges += '<span class="text-xs bg-green-500 text-white px-1.5 py-0.5 rounded ml-2">newer</span>';
      }
      if (!isStable) {
        badges += '<span class="text-xs bg-yellow-500 text-white px-1.5 py-0.5 rounded ml-2">dev</span>';
      }

      // Update button - recommend stable versions more prominently
      let updateBtn;
      if (isCurrent) {
        updateBtn = '<span class="text-xs text-gray-400">installed</span>';
      } else if (isNewer && isStable) {
        updateBtn = `<button class="version-update-btn px-3 py-1 text-xs bg-green-500 text-white rounded hover:bg-green-600 font-medium" data-tag="${version.tag}">Update</button>`;
      } else if (isNewer && !isStable) {
        updateBtn = `<button class="version-update-btn px-3 py-1 text-xs bg-yellow-500 text-white rounded hover:bg-yellow-600" data-tag="${version.tag}">Dev</button>`;
      } else {
        updateBtn = `<button class="version-update-btn px-3 py-1 text-xs bg-gray-300 text-gray-700 rounded hover:bg-gray-400" data-tag="${version.tag}">Switch</button>`;
      }

      html += `
        <div class="flex items-center justify-between p-2 hover:bg-gray-50 rounded ${badgeClass}">
          <div class="flex items-center">
            <code class="font-mono text-sm">${version.tag}</code>
            ${badges}
          </div>
          ${updateBtn}
        </div>
      `;
    }

    html += '</div>';
    listEl.innerHTML = html;

    // Add click handlers for update buttons
    listEl.querySelectorAll('.version-update-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        const newTag = btn.dataset.tag;
        confirmVersionUpdate(serverName, containerName, image, newTag);
      });
    });

  } catch (error) {
    console.error('Failed to fetch versions:', error);
    listEl.innerHTML = `
      <div class="text-center py-8 text-red-500">
        Failed to load versions: ${error.message}
      </div>
    `;
  }
}

// Track in-flight updates to prevent duplicates
const pendingUpdates = new Set();

/**
 * Execute version update (confirmation already handled by caller).
 */
async function confirmVersionUpdate(serverName, containerName, currentImage, newTag) {
  // Prevent duplicate update requests
  const updateKey = `${serverName}:${containerName}`;
  if (pendingUpdates.has(updateKey)) {
    console.log(`Update already pending for ${containerName}, ignoring duplicate`);
    return;
  }
  pendingUpdates.add(updateKey);

  const baseImage = currentImage.split(':')[0];
  const newImage = `${baseImage}:${newTag}`;
  const currentTag = currentImage.split(':')[1] || 'latest';

  // Close version modal
  document.getElementById('version-modal')?.classList.add('hidden');

  // Show update in progress
  const progressModal = document.getElementById('update-in-progress-modal');
  const containerNameEl = document.getElementById('update-container-name');
  if (progressModal && containerNameEl) {
    containerNameEl.textContent = containerName;
    progressModal.classList.remove('hidden');
  }

  try {
    // Call update endpoint with new image
    const response = await fetch(`${API_PREFIX}/update-container`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        server_name: serverName,
        container_name: containerName,
        new_image: newImage
      })
    });

    const result = await response.json();
    progressModal?.classList.add('hidden');

    if (result.error) {
      showUpdateError(result.error);
    } else if (result.status === 'in_progress') {
      // Another request is already handling this update - ignore
      console.log('Update already in progress, ignoring duplicate response');
    } else {
      showUpdateSuccess(containerName, currentTag, newTag);
      // Clear cache and refresh
      versionCache.delete(currentImage);
      versionCache.delete(newImage);
      // Trigger data refresh
      if (typeof window.fetchContainerData === 'function') {
        window.fetchContainerData();
      }
    }
  } catch (error) {
    progressModal?.classList.add('hidden');
    showUpdateError(error.message);
  } finally {
    // Clear pending flag
    pendingUpdates.delete(`${serverName}:${containerName}`);
  }
}

function showUpdateSuccess(containerName, fromTag, toTag) {
  const modal = document.getElementById('update-success-modal');
  const messageEl = document.getElementById('update-success-message');
  if (modal && messageEl) {
    messageEl.innerHTML = `<strong>${containerName}</strong> updated from <code>${fromTag}</code> to <code>${toTag}</code>`;
    modal.classList.remove('hidden');
  }
}

function showUpdateError(message) {
  const modal = document.getElementById('update-error-modal');
  const messageEl = document.getElementById('update-error-message');
  if (modal && messageEl) {
    messageEl.textContent = message;
    modal.classList.remove('hidden');
  }
}

/**
 * Initialize version check modal handlers.
 */
export function initVersionModal() {
  const modal = document.getElementById('version-modal');
  const closeBtn = document.getElementById('version-modal-close');
  const okBtn = document.getElementById('version-modal-ok');

  if (closeBtn) {
    closeBtn.addEventListener('click', () => modal?.classList.add('hidden'));
  }

  if (okBtn) {
    okBtn.addEventListener('click', () => modal?.classList.add('hidden'));
  }

  if (modal) {
    modal.addEventListener('click', (e) => {
      if (e.target === modal) modal.classList.add('hidden');
    });
  }

  // Initialize success modal handlers
  const successModal = document.getElementById('update-success-modal');
  const successOkBtn = document.getElementById('update-success-ok-button');

  if (successOkBtn) {
    successOkBtn.addEventListener('click', () => {
      successModal?.classList.add('hidden');
    });
  }

  if (successModal) {
    successModal.addEventListener('click', (e) => {
      if (e.target === successModal) successModal.classList.add('hidden');
    });
  }

  // Initialize error modal handlers
  const errorModal = document.getElementById('update-error-modal');
  const errorOkBtn = document.getElementById('update-error-ok-button');

  if (errorOkBtn) {
    errorOkBtn.addEventListener('click', () => {
      errorModal?.classList.add('hidden');
    });
  }

  if (errorModal) {
    errorModal.addEventListener('click', (e) => {
      if (e.target === errorModal) errorModal.classList.add('hidden');
    });
  }

  // Listen for clicks on new version indicators (single-click update to latest)
  document.addEventListener('click', async (e) => {
    const indicator = e.target.closest('.new-version-indicator');
    if (indicator) {
      e.preventDefault();
      e.stopPropagation();

      const serverName = indicator.dataset.server;
      const containerName = indicator.dataset.container;
      const image = indicator.dataset.image;
      const latestVersion = indicator.dataset.latestVersion;

      if (serverName && containerName && image && latestVersion) {
        // Single-click update to latest version
        const baseImage = image.split(':')[0];
        const currentTag = image.split(':')[1] || 'latest';

        try {
          await showConfirmationModal(
            `Update ${containerName}?`,
            `Update to latest version?\n\nFrom: ${currentTag}\nTo: ${latestVersion}\n\nThis will pull the new image and recreate the container.`,
            'Update'
          );
          // User confirmed
          confirmVersionUpdate(serverName, containerName, image, latestVersion);
        } catch (err) {
          // User cancelled - do nothing
        }
      }
    }
  });

  // Listen for clicks on image name to open version selection modal
  document.addEventListener('click', (e) => {
    const imageCode = e.target.closest('.table-cell-image code');
    if (imageCode && imageCode.dataset.hasNewVersion === 'true') {
      e.preventDefault();
      e.stopPropagation();

      const serverName = imageCode.dataset.server;
      const containerName = imageCode.dataset.container;
      const image = imageCode.dataset.image;

      if (serverName && containerName && image) {
        showVersionModal(serverName, containerName, image);
      }
    }
  });
}

/**
 * Clear the version cache.
 */
export function clearVersionCache() {
  versionCache.clear();
}
