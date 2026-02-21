import { STATUS_CLASSES, EXIT_CODE_MESSAGES } from './constants.js';
import { calculateUptime } from './uptime.js';

export function renderStatus(container) {
  const span = document.createElement('span');
  span.textContent = container.status;

  if (container.exit_code != null) {
    span.setAttribute('data-tooltip', getExitCodeTooltip(container.exit_code));
  } else {
    span.setAttribute('data-tooltip', getStatusTooltip(container));
  }

  return { span, className: getStatusClass(container) };
}

function getExitCodeTooltip(exitCode) {
  const message = EXIT_CODE_MESSAGES[exitCode];
  return message ? `Exit code: ${exitCode} (${message})` : `Exit code: ${exitCode}`;
}

function getStatusTooltip(container) {
  const uptime = calculateUptime(container.started_at);
  const baseMessages = {
    running: 'Container is running',
    healthy: 'Health check passed',
    unhealthy: 'Health check failed',
    starting: 'Container is starting up',
    paused: 'Container is paused',
    restarting: 'Container is restarting',
    removing: 'Container is being removed',
    dead: 'Container is dead (cannot be restarted)',
    created: 'Container created but not started'
  };

  let message = baseMessages[container.status] || `Container status: ${container.status}`;

  if (uptime) {
    if (container.status === 'starting') {
      message += ` (starting for: ${uptime})`;
    } else if (container.status === 'paused') {
      message += ` (was up: ${uptime})`;
    } else if (['running', 'healthy', 'unhealthy'].includes(container.status)) {
      message += ` (up: ${uptime})`;
    }
  }

  return message;
}

function getStatusClass(container) {
  const swarmMatch = container.status?.match(/^running \((\d+)\/(\d+)\)$/);
  if (swarmMatch) {
    const [, running, desired] = swarmMatch.map(Number);
    return running === desired ? STATUS_CLASSES.running : STATUS_CLASSES.unhealthy;
  }

  if (container.status?.includes('exited')) return STATUS_CLASSES.exited;
  if (container.status?.includes('health unknown')) return STATUS_CLASSES.running;

  return STATUS_CLASSES[container.status] || 'status-unknown';
}
